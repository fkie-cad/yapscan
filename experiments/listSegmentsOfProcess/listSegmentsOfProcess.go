package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/dustin/go-humanize"
	"github.com/fkie-cad/yapscan/procio"
)

func main() {
	if len(os.Args) != 2 && len(os.Args) != 3 {
		fmt.Printf("Usage: %s <pid> [all]\n", os.Args[0])
		os.Exit(1)
	}

	pid, err := strconv.Atoi(os.Args[1])
	if err != nil {
		panic(err)
	}

	all := false
	if len(os.Args) == 3 {
		all = true
	}

	fmt.Printf("Reading segments from process %d...\n", pid)
	proc, err := procio.OpenProcess(pid)
	if err != nil {
		panic(err)
	}
	defer proc.Close()
	segments, err := proc.MemorySegments()
	for _, seg := range segments {
		fmt.Printf("0x%016x : %8s : %7v : %7v : %v : %v\n", seg.BaseAddress, humanize.Bytes(uint64(seg.Size)), seg.Type, seg.State, seg.AllocatedPermissions, seg.CurrentPermissions)
		if all {
			for _, subSeg := range seg.SubSegments {
				fmt.Printf("    0x%016x : %8s : %7v : %7v : %v : %v\n", subSeg.BaseAddress, humanize.Bytes(uint64(subSeg.Size)), subSeg.Type, subSeg.State, subSeg.AllocatedPermissions, subSeg.CurrentPermissions)
			}
		}
	}
	if err != nil {
		panic(err)
	}
}
