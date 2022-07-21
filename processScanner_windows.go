package yapscan

func isSuitableForOptimization(seg *procio.MemorySegmentInfo) bool {
	return false
}

func readSegmentOptimized(proc procio.Process, seg *procio.MemorySegmentInfo, rdr procio.MemoryReader, data []byte) error {
	return nil
}
