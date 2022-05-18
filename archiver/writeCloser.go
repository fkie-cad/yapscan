package archiver

import "io"

type callbackWriteCloser struct {
	writer io.Writer
	close  func() error
}

func (w *callbackWriteCloser) Write(p []byte) (n int, err error) {
	return w.writer.Write(p)
}

func (w *callbackWriteCloser) Close() error {
	if w.close == nil {
		return nil
	}
	return w.close()
}
