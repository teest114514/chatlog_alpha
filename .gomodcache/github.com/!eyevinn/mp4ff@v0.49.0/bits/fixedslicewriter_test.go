package bits_test

import (
	"bytes"
	"testing"

	"github.com/Eyevinn/mp4ff/bits"
)

func TestFixedSliceWriter(t *testing.T) {
	t.Run("Write uints and overflow", func(t *testing.T) {
		sw := bits.NewFixedSliceWriter(20)
		sw.WriteUint8(0xff)
		sw.WriteUint16(0xffff)
		sw.WriteUint24(0xffffff)
		sw.WriteUint32(0xffffffff)
		sw.WriteUint64(0xffffffffffffffff)
		sw.WriteUint16(0)
		expected := make([]byte, 20)
		for i := range expected {
			if i == 18 {
				break
			}
			expected[i] = 0xff
		}
		if !bytes.Equal(expected, sw.Bytes()) {
			t.Errorf("bytes differ: %v %v", expected, sw.Bytes())
		}
		sw.WriteUint24(0xffffff)
		if sw.AccError() == nil {
			t.Errorf("no overflow error")
		}
		// Write past end of slice (should not panic)
		sw.WriteUint8(0xff)
		sw.WriteUint16(0xffff)
		sw.WriteUint32(0xffffffff)
		sw.WriteUint48(0xffffffffffff)
		sw.WriteUint64(0xffffffff00112233)
		sw.WriteInt16(-1)
		sw.WriteInt32(-1)
		sw.WriteInt64(-1)
		sw.WriteString("hello", true)
		sw.WriteBytes([]byte{0x01, 0x02, 0x03})
		sw.WriteZeroBytes(7)
		sw.WriteUnityMatrix()
		sw.WriteBits(0x0f, 4)
		sw.FlushBits()
		if sw.AccError() == nil {
			t.Errorf("no overflow error")
		}
	})
	t.Run("write signed", func(t *testing.T) {
		s := make([]byte, 14)
		sw := bits.NewFixedSliceWriterFromSlice(s)
		sw.WriteInt16(-1)
		sw.WriteInt32(-2)
		sw.WriteInt64(-1)
		if sw.AccError() != nil {
			t.Errorf("unexpected error writing signed")
		}
		expected := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
		if !bytes.Equal(expected, sw.Bytes()) {
			t.Errorf("bytes differ: %v %v", expected, sw.Bytes())
		}
	})
	t.Run("write other", func(t *testing.T) {
		sw := bits.NewFixedSliceWriter(55)
		sw.WriteUint48(0x123456789abc)
		sw.WriteZeroBytes(3)
		sw.WriteBytes([]byte{0x01, 0x02, 0x03})
		sw.WriteString("hello", true)
		sw.WriteUnityMatrix()
		sw.WriteFlag(false)
		sw.WriteFlag(true)
		sw.FlushBits()
		if sw.AccError() != nil {
			t.Errorf("unexpected error writing other")
		}
		expected := []byte{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03,
			0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x00,
			0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
			0x40}
		if !bytes.Equal(sw.Bytes(), expected) {
			t.Errorf("bytes differ: %v %v", expected, sw.Bytes())
		}
	})
	t.Run("write bits", func(t *testing.T) {
		s := make([]byte, 4)
		sw := bits.NewFixedSliceWriterFromSlice(s)
		cap := sw.Capacity()
		if cap != 4 {
			t.Errorf("unexpected capacity %d", cap)
		}
		sw.WriteBits(0xf, 4)
		sw.WriteBits(0x2, 4)
		sw.WriteBits(0x5, 4)
		sw.FlushBits()
		if sw.AccError() != nil {
			t.Errorf("unexpected error writing bits")
		}
		wantedOffset := 2
		offset := sw.Offset()
		if offset != wantedOffset {
			t.Errorf("unexpected offset %d instead of %d", offset, wantedOffset)
		}
		result := sw.Bytes()
		if result[0] != 0xf2 || result[1] != 0x50 {
			t.Errorf("got %02x%02x instead of 0xf250", result[0], result[1])
		}
		sw.WriteUint16(0xffff)
		if sw.Len() != 4 {
			t.Errorf("unexpected length %d after 4 bytes", sw.Len())
		}
	})
}
