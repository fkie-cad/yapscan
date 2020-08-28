package procIO

import (
	"io"
)

type MemoryReader interface {
	io.ReadCloser
}
