package testutil

import (
	"errors"
	"path/filepath"
	"runtime"
)

func GetProjectRoot() (string, error) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		return "", errors.New("could not determine caller")
	}

	dir := filepath.Dir(filename)
	path := filepath.Join(dir, "..")

	return filepath.Clean(path), nil
}
