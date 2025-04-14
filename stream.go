package coraza

import (
	"io"

	"github.com/corazawaf/coraza/v3/types"
)

// Copy our stream types into the test file
type StreamReader struct {
	Transaction types.Transaction
	Reader      io.Reader
}

func (sr *StreamReader) Read(p []byte) (n int, err error) {
	n, err = sr.Reader.Read(p)
	if n > 0 {
		if it, _, writeErr := sr.Transaction.WriteRequestBody(p[:n]); it != nil || writeErr != nil {
			return 0, io.EOF
		}
	}
	return
}

type StreamWriter struct {
	Transaction types.Transaction
	Writer      io.Writer
}

func (sw *StreamWriter) Write(p []byte) (n int, err error) {
	// First write to the transaction
	if it, _, writeErr := sw.Transaction.WriteRequestBody(p); it != nil || writeErr != nil {
		return 0, io.EOF
	}
	// Then write to the underlying writer
	return sw.Writer.Write(p)
}
