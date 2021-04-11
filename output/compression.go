package output

import (
	"io"

	"github.com/klauspost/compress/zstd"
)

func NewZSTDCompressor(out io.Writer) io.WriteCloser {
	zstdWriter, err := zstd.NewWriter(out)
	if err != nil {
		// This should only happen if we (the dev) screw up with the options
		panic(err)
	}
	return zstdWriter
}
