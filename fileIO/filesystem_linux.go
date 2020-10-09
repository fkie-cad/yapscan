package fileIO

import (
	"path/filepath"
	"strings"
)

var skippedRoots = []string{
	"/dev",
	"/proc",
	"/sys",
}

var skippedDirs = []string{
	"lost+found",
}

func doScanDir(path string) bool {
	var err error
	path, err = filepath.Abs(path)
	if err != nil {
		return false
	}

	for _, root := range skippedRoots {
		if len(path) < len(root) {
			continue
		}
		if path[:len(root)] == root {
			// starts with root but may still be a different directory
			if len(path) == len(root) || path[len(root)] == '/' {
				return false
			}
		}
	}
	for _, dir := range skippedDirs {
		if strings.Contains(path, "/"+dir) {
			if len(path) == len(dir)+1 || path[len(dir)+1] == '/' {
				return false
			}
		}
	}
	return true
}
