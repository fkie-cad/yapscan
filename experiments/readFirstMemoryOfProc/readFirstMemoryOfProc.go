package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/fkie-cad/yapscan/procIO"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Printf("Usage: %s <pid> <length>\n", os.Args[0])
		os.Exit(1)
	}

	pid, err := strconv.Atoi(os.Args[1])
	if err != nil {
		panic(err)
	}

	length, err := strconv.Atoi(os.Args[2])
	if err != nil {
		panic(err)
	}

	fmt.Printf("Reading segments from process %d...\n", pid)
	proc, err := procIO.OpenProcess(pid)
	if err != nil {
		panic(err)
	}
	defer proc.Close()
	segments, err := proc.MemorySegments()
	if err != nil {
		panic(err)
	}

	readSeg := segments[0]

	rdr, _ := procIO.NewMemoryReader(proc, readSeg)
	defer rdr.Close()

	if length > 0 {
		buffer := make([]byte, length)
		_, err = io.ReadFull(rdr, buffer)
		if err != nil {
			panic(err)
		}

		fmt.Printf("Read at 0x%016x:\n", readSeg.BaseAddress)
		fmt.Printf("%s", hex.Dump(buffer))
	} else {
		dumper := hex.Dumper(os.Stdout)
		defer dumper.Close()

		fmt.Printf("Read at 0x%016x:\n", readSeg.BaseAddress)
		_, err := io.Copy(dumper, rdr)
		if err != nil {
			panic(err)
		}
	}
}
