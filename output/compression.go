package output

import (
	"github.com/klauspost/compress/zstd"
	"io"
)

func NewZSTDCompressor(out io.WriteCloser) io.WriteCloser {
	zstdWriter, err := zstd.NewWriter(out)
	if err != nil {
		// This should only happen if we (the dev) screw up with the options
		panic(err)
	}
	return &decoratedWriteCloser{
		writer: zstdWriter,
		base:   out,
		meta: map[string]interface{}{
			metaKeySuggestedFileExtension: ".zstd",
		},
	}
}
