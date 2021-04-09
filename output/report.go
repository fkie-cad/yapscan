package output

import (
	"encoding/json"
	"io"
)

type EncoderCloser interface {
	io.Closer
	Encode(v interface{}) error
}

type jsonEncoder struct {
	enc    *json.Encoder
	output io.Closer
}

func NewJsonEncoder(output io.WriteCloser) EncoderCloser {
	return &jsonEncoder{
		enc:    json.NewEncoder(output),
		output: output,
	}
}

func (e *jsonEncoder) Close() error {
	return e.output.Close()
}

func (e *jsonEncoder) Encode(v interface{}) error {
	return e.enc.Encode(v)
}
