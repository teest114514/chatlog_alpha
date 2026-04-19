package bits_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/Eyevinn/mp4ff/bits"
)

func TestByteWriter(t *testing.T) {
	t.Run("write ints", func(t *testing.T) {
		buf := bytes.Buffer{}
		w := bits.NewByteWriter(&buf)
		if w.AccError() != nil {
			t.Error("Error should be nil")
		}
		w.WriteUint8(0x00)
		w.WriteUint16(0x0102)
		w.WriteUint32(0x03040506)
		w.WriteUint48(0x0708090a0b0c)
		w.WriteUint64(0x0d0e0f1011121314)
		w.WriteSlice([]byte{0x15, 0x16, 0x17})
		if w.AccError() != nil {
			t.Errorf("unexpected error: %v", w.AccError())
		}
		expected := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
			0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17}
		if !bytes.Equal(expected, buf.Bytes()) {
			t.Errorf("bytes differ: %v %v", expected, buf.Bytes())
		}
	})
	t.Run("write after error", func(t *testing.T) {
		buf := newLimitedBuffer(1)
		w := bits.NewByteWriter(buf)
		w.WriteUint8(0x77)
		if w.AccError() != nil {
			t.Error("limited buffer should accept 1 byte")
		}
		w.WriteUint48(0x00)
		if w.AccError() == nil {
			t.Error("limited buffer should not accept any more bytes")
		}
		w.WriteUint8(0x01)
		if w.AccError() == nil {
			t.Error("limited buffer should not accept 2 bytes")
		}
		w.WriteUint16(0x0102)
		if w.AccError() == nil {
			t.Error("limited buffer should have an accumulated error")
		}
		w.WriteUint32(0x03040506)
		if w.AccError() == nil {
			t.Error("limited buffer should have an accumulated error")
		}
		w.WriteUint48(0x0708090a0b0c)
		if w.AccError() == nil {
			t.Error("limited buffer should have an accumulated error")
		}
		w.WriteUint64(0x0d0e0f1011121314)
		if w.AccError() == nil {
			t.Error("limited buffer should have an accumulated error")
		}
		w.WriteSlice([]byte{0x15, 0x16, 0x17})
		if w.AccError() == nil {
			t.Error("limited buffer should have an accumulated error")
		}
		expected := []byte{0x77}
		if !bytes.Equal(expected, buf.buf) {
			t.Errorf("bytes differ: %v %v", expected, buf.buf)
		}
	})

}

type limitedBuffer struct {
	limit int
	buf   []byte
}

func newLimitedBuffer(limit int) *limitedBuffer {
	return &limitedBuffer{limit: limit, buf: make([]byte, 0, limit)}
}

func (lb *limitedBuffer) Write(p []byte) (n int, err error) {
	if len(lb.buf)+len(p) > lb.limit {
		return 0, fmt.Errorf("overflow")
	}
	lb.buf = append(lb.buf, p...)
	return len(p), nil
}
