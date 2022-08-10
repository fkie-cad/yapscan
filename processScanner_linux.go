package yapscan

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/fkie-cad/yapscan/procio"
	"github.com/sirupsen/logrus"
)

type PagemapEntry struct {
	PFN         uint64
	IsSoftDirty bool
	IsFilePage  bool
	IsSwapped   bool
	IsPresent   bool
}

func getPagemapEntry(file *os.File, vaddr uintptr) (*PagemapEntry, error) {
	const pagemapEntrySize = 8
	offset := vaddr / uintptr(os.Getpagesize()) * pagemapEntrySize
	_, err := file.Seek(int64(offset), io.SeekStart)
	if err != nil {
		return nil, fmt.Errorf("Failed to seek offset in pagemapfile: %v", err)
	}
	buffer := make([]byte, pagemapEntrySize)
	_, err = file.Read(buffer)
	if err != nil {
		return nil, fmt.Errorf("Failed to read bytes from pagemap file into buffer: %v", err)
	}

	value := binary.LittleEndian.Uint64(buffer)
	return &PagemapEntry{
		PFN:         value & ((uint64(1 << 54)) - 1),
		IsSoftDirty: ((value >> 54) & 1) != 0,
		IsFilePage:  ((value >> 61) & 1) != 0,
		IsSwapped:   ((value >> 62) & 1) != 0,
		IsPresent:   ((value >> 63) & 1) != 0,
	}, nil
}

func isSuitableForOptimization(seg *procio.MemorySegmentInfo) bool {
	// check if seg is file backed
	if seg.MappedFile == nil ||
		seg.MappedFile.Device() == 0 ||
		seg.MappedFile.Inode() == 0 {
		return false
	}

	// check able to open file
	f, err := os.OpenFile(seg.MappedFile.Path(), os.O_RDONLY, 0400)
	if err != nil {
		// Segment is file backed but could not open file
		return false
	}
	defer f.Close()

	// check stat
	fileInfo, err := os.Stat(seg.MappedFile.Path())
	if err != nil {
		// Segment is file backed, file can be opened but no file info can be obtained
		return false
	}

	// check inode and device id
	if seg.MappedFile.Device() != fileInfo.Sys().(*syscall.Stat_t).Dev ||
		seg.MappedFile.Inode() != fileInfo.Sys().(*syscall.Stat_t).Ino {
		return false
	}

	// check size+offset fits
	if fileInfo.Size() >= 0 &&
		uint64(fileInfo.Size()) < seg.MappedFile.Offset()+uint64(seg.Size) {
		// Mapping extends past end of file. Treat like missing.
		return false
	}

	// check is regular file
	if !fileInfo.Mode().IsRegular() {
		// Correct filesystem object, but not a regular file.
		return false
	}

	return true
}

func readSegmentOptimized(proc procio.Process, seg *procio.MemorySegmentInfo, rdr procio.MemoryReader, data []byte) error {
	pagemapFile, err := os.Open(fmt.Sprintf("/proc/%d/pagemap", proc.PID()))
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"process":       proc,
			"segment":       seg,
			logrus.ErrorKey: err,
		}).Error("Could not open pagemap file of process.")
		return err
	}
	defer pagemapFile.Close()

	mappedFile, _ := os.Open(seg.MappedFile.Path())
	defer mappedFile.Close()

	_, err = mappedFile.Seek(int64(seg.MappedFile.Offset()), io.SeekStart)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"process":       proc,
			"segment":       seg,
			logrus.ErrorKey: err,
		}).Error("Could not seek mapped file to offset.")
		return err
	}

	io.ReadFull(mappedFile, data)

	currentAddress := seg.BaseAddress
	for currentAddress < seg.BaseAddress+seg.Size {
		pagemapEntry, err := getPagemapEntry(pagemapFile, currentAddress)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"process":       proc,
				"segment":       seg,
				logrus.ErrorKey: err,
			}).Error("Could not read pagemap entry of process.")
			return err
		}

		if pagemapEntry.IsPresent {
			offset := currentAddress - seg.BaseAddress
			rdr.Seek(int64(offset), io.SeekStart)
			rdr.Read(data[offset : int(offset)+os.Getpagesize()])
		}

		currentAddress += uintptr(os.Getpagesize())
	}

	return nil
}
