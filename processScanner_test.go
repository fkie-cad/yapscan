package yapscan

import (
	"bytes"
	"fmt"
	"os"
	"testing"

	"github.com/fkie-cad/yapscan/procIO"

	"github.com/hillu/go-yara/v4"
	"github.com/targodan/go-errors"

	. "github.com/smartystreets/goconvey/convey"
	"github.com/stretchr/testify/mock"
)

func TestPorcessScan(t *testing.T) {
	mockedProc := new(mockProcess)
	defer mockedProc.AssertExpectations(t)
	mockedMemoryScanner := new(MockMemoryScanner)
	defer mockedMemoryScanner.AssertExpectations(t)
	mockedSegmentScanner := new(mockSegmentScanner)
	defer mockedSegmentScanner.AssertExpectations(t)

	Convey("A ProcessScanner", t, func() {
		ps := NewProcessScanner(mockedProc, nil, mockedMemoryScanner)
		ps.scanner = mockedSegmentScanner

		Convey("should not be nil.", func() {
			So(ps, ShouldNotBeNil)
		})

		Convey("scanning an erroring process", func() {
			underlyingErr := errors.New("underlying error")
			mockedProc.On("MemorySegments").Return(nil, underlyingErr).Once()

			c, err := ps.Scan()

			Convey("should error itself.", func() {
				So(c, ShouldBeNil)
				So(err, ShouldNotBeNil)
			})
		})

		Convey("scanning a valid process", func() {
			segments := []*procIO.MemorySegmentInfo{
				&procIO.MemorySegmentInfo{ // This should not be scanned, it's not a leaf
					ParentBaseAddress:    1,
					BaseAddress:          1,
					AllocatedPermissions: procIO.Permissions{},
					CurrentPermissions:   procIO.Permissions{},
					Size:                 0,
					State:                0,
					Type:                 0,
					FilePath:             "",
					SubSegments: []*procIO.MemorySegmentInfo{
						&procIO.MemorySegmentInfo{
							ParentBaseAddress:    1,
							BaseAddress:          2,
							AllocatedPermissions: procIO.Permissions{},
							CurrentPermissions:   procIO.Permissions{},
							Size:                 0,
							State:                0,
							Type:                 0,
							FilePath:             "",
							SubSegments:          nil,
						},
						&procIO.MemorySegmentInfo{
							ParentBaseAddress:    1,
							BaseAddress:          3,
							AllocatedPermissions: procIO.Permissions{},
							CurrentPermissions:   procIO.Permissions{},
							Size:                 0,
							State:                0,
							Type:                 0,
							FilePath:             "",
							SubSegments:          nil,
						},
					},
				},
				&procIO.MemorySegmentInfo{
					ParentBaseAddress:    4,
					BaseAddress:          4,
					AllocatedPermissions: procIO.Permissions{},
					CurrentPermissions:   procIO.Permissions{},
					Size:                 0,
					State:                0,
					Type:                 0,
					FilePath:             "",
					SubSegments:          nil,
				},
				&procIO.MemorySegmentInfo{
					ParentBaseAddress:    5,
					BaseAddress:          5,
					AllocatedPermissions: procIO.Permissions{},
					CurrentPermissions:   procIO.Permissions{},
					Size:                 0,
					State:                0,
					Type:                 0,
					FilePath:             "",
					SubSegments:          nil,
				},
			}
			mockedProc.On("MemorySegments").Return(segments, nil).Once()

			Convey("without any errors", func() {
				expectedProgress := []*MemoryScanProgress{
					&MemoryScanProgress{
						Process:       mockedProc,
						MemorySegment: segments[0].SubSegments[0],
						Dump:          nil,
						Matches:       nil,
						Error:         nil,
					},
					&MemoryScanProgress{
						Process:       mockedProc,
						MemorySegment: segments[0].SubSegments[1],
						Dump:          []byte("some data"),
						Matches:       make([]yara.MatchRule, 0),
						Error:         nil,
					},
					&MemoryScanProgress{
						Process:       mockedProc,
						MemorySegment: segments[1],
						Dump:          []byte("some other data"),
						Matches:       make([]yara.MatchRule, 2),
						Error:         nil,
					},
					&MemoryScanProgress{
						Process:       mockedProc,
						MemorySegment: segments[2],
						Dump:          []byte(""),
						Matches:       nil,
						Error:         nil,
					},
				}

				mockedSegmentScanner.
					On("ScanSegment", segments[0].SubSegments[0]).
					Return(expectedProgress[0].Matches, expectedProgress[0].Dump, expectedProgress[0].Error).
					Once().
					On("ScanSegment", segments[0].SubSegments[1]).
					Return(expectedProgress[1].Matches, expectedProgress[1].Dump, expectedProgress[1].Error).
					Once().
					On("ScanSegment", segments[1]).
					Return(expectedProgress[2].Matches, expectedProgress[2].Dump, expectedProgress[2].Error).
					Once().
					On("ScanSegment", segments[2]).
					Return(expectedProgress[3].Matches, expectedProgress[3].Dump, expectedProgress[3].Error).
					Once()

				c, err := ps.Scan()
				Convey("should not error.", func() {
					So(c, ShouldNotBeNil)
					So(err, ShouldBeNil)
				})
				if err != nil {
					return
				}

				received := make([]*MemoryScanProgress, 0, 4)
				for prog := range c {
					received = append(received, prog)
				}

				Convey("should yield the expected data.", func() {
					So(received, ShouldResemble, expectedProgress)
				})
			})

			Convey("with errors", func() {
				expectedProgress := []*MemoryScanProgress{
					&MemoryScanProgress{
						Process:       mockedProc,
						MemorySegment: segments[0].SubSegments[0],
						Dump:          nil,
						Matches:       nil,
						Error:         errors.New("some error"),
					},
					&MemoryScanProgress{
						Process:       mockedProc,
						MemorySegment: segments[0].SubSegments[1],
						Dump:          []byte("some data"),
						Matches:       make([]yara.MatchRule, 0),
						Error:         errors.New("some other error"),
					},
					&MemoryScanProgress{
						Process:       mockedProc,
						MemorySegment: segments[1],
						Dump:          []byte("some other data"),
						Matches:       make([]yara.MatchRule, 2),
						Error:         fmt.Errorf("some permission error, %w", os.ErrPermission),
					},
				}
				mockedSegmentScanner.
					On("ScanSegment", segments[0].SubSegments[0]).
					Return(expectedProgress[0].Matches, expectedProgress[0].Dump, expectedProgress[0].Error).
					Once().
					On("ScanSegment", segments[0].SubSegments[1]).
					Return(expectedProgress[1].Matches, expectedProgress[1].Dump, expectedProgress[1].Error).
					Once().
					On("ScanSegment", segments[1]).
					Return(expectedProgress[2].Matches, expectedProgress[2].Dump, expectedProgress[2].Error).
					Once()

				c, err := ps.Scan()
				Convey("should not error.", func() {
					So(c, ShouldNotBeNil)
					So(err, ShouldBeNil)
				})
				if err != nil {
					return
				}

				received := make([]*MemoryScanProgress, 0, 4)
				for prog := range c {
					received = append(received, prog)
				}

				Convey("should yield the expected data.", func() {
					So(received, ShouldResemble, expectedProgress)
				})
			})
		})
	})
}

type mockMemoryReaderWithBuffer struct {
	buffer *bytes.Buffer
	err    error
}

func (rdr *mockMemoryReaderWithBuffer) Read(p []byte) (n int, err error) {
	n, err = rdr.buffer.Read(p)
	if rdr.err != nil {
		err = rdr.err
	}
	return
}

func (rdr *mockMemoryReaderWithBuffer) Seek(offset int64, whence int) (int64, error) {
	panic("seeking not implemented in mock")
}

func (rdr *mockMemoryReaderWithBuffer) Close() error {
	return nil
}

func TestSegmentScanner(t *testing.T) {
	Convey("Scanning a filtered segment", t, func() {
		mockedProc := new(mockProcess)
		defer mockedProc.AssertExpectations(t)
		mockedFilter := new(MockMemorySegmentFilter)
		defer mockedFilter.AssertExpectations(t)
		mockedMemoryScanner := new(MockMemoryScanner)
		defer mockedMemoryScanner.AssertExpectations(t)

		sc := &defaultSegmentScanner{
			proc:    mockedProc,
			filter:  mockedFilter,
			scanner: mockedMemoryScanner,
		}

		mockedFilter.On("Filter", mock.Anything).Return(&FilterMatch{
			Result: false,
			MSI:    nil,
			Reason: "skipped",
		})

		match, data, err := sc.ScanSegment(&procIO.MemorySegmentInfo{})

		Convey("should yield the appropriate skip error.", func() {
			So(match, ShouldBeNil)
			So(data, ShouldBeNil)
			So(err, ShouldResemble, ErrSkipped)
		})
	})

	Convey("Scanning a non-filtered segment", t, func() {
		mockedProc := new(mockProcess)
		defer mockedProc.AssertExpectations(t)
		mockedFilter := new(MockMemorySegmentFilter)
		defer mockedFilter.AssertExpectations(t)
		mockedMemoryScanner := new(MockMemoryScanner)
		defer mockedMemoryScanner.AssertExpectations(t)

		sc := &defaultSegmentScanner{
			proc:    mockedProc,
			filter:  mockedFilter,
			scanner: mockedMemoryScanner,
		}

		mockedFilter.On("Filter", mock.Anything).Return(&FilterMatch{
			Result: true,
			MSI:    nil,
			Reason: "",
		})

		Convey("with an error during reader creation", func() {
			mockedFactory := new(mockMemoryReaderFactory)
			defer mockedFactory.AssertExpectations(t)

			expErr := errors.New("some error")
			mockedFactory.On("NewMemoryReader", mock.Anything, mock.Anything).Return(nil, expErr)

			sc.rdrFactory = mockedFactory
			match, data, err := sc.ScanSegment(&procIO.MemorySegmentInfo{})

			Convey("should yield the underlying error.", func() {
				So(match, ShouldBeNil)
				So(data, ShouldBeNil)
				So(err, ShouldEqual, expErr)
			})
		})

		Convey("with errors during read", func() {
			mockedFactory := new(mockMemoryReaderFactory)
			defer mockedFactory.AssertExpectations(t)

			memoryData := []byte("some data")

			mockRdr := &mockMemoryReaderWithBuffer{
				buffer: bytes.NewBuffer(memoryData),
				err:    errors.New("whoops, something happened"),
			}

			mockedFactory.On("NewMemoryReader", mock.Anything, mock.Anything).
				Return(mockRdr, nil)

			sc.rdrFactory = mockedFactory
			match, data, err := sc.ScanSegment(&procIO.MemorySegmentInfo{})

			Convey("should yield the error.", func() {
				So(match, ShouldBeNil)
				So(data, ShouldBeNil)
				So(err, ShouldEqual, mockRdr.err)
			})
		})

		Convey("without any errors", func() {
			mockedFactory := new(mockMemoryReaderFactory)
			defer mockedFactory.AssertExpectations(t)

			memoryData := []byte("some data")

			mockRdr := &mockMemoryReaderWithBuffer{
				buffer: bytes.NewBuffer(memoryData),
				err:    nil,
			}

			mockedFactory.On("NewMemoryReader", mock.Anything, mock.Anything).
				Return(mockRdr, nil)

			expMatches := make([]yara.MatchRule, 2)
			expErr := errors.New("some err")
			mockedMemoryScanner.On("ScanMem", memoryData).Return(expMatches, expErr).Once()

			sc.rdrFactory = mockedFactory
			match, data, err := sc.ScanSegment(&procIO.MemorySegmentInfo{})

			Convey("should yield the expected data.", func() {
				So(match, ShouldResemble, expMatches)
				So(data, ShouldResemble, memoryData)
				So(err, ShouldEqual, expErr)
			})
		})
	})
}
