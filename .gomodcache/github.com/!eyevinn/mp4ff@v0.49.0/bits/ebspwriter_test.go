package bits_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/Eyevinn/mp4ff/bits"
	"github.com/go-test/deep"
)

func TestEBSPWriter(t *testing.T) {
	t.Run("insert startcode emulation prevention bytes", func(t *testing.T) {
		testCases := []struct {
			in  []byte
			out []byte
		}{
			{
				in:  []byte{0, 0, 0, 1},
				out: []byte{0, 0, 3, 0, 1},
			},
			{
				in:  []byte{1, 0, 0, 2},
				out: []byte{1, 0, 0, 3, 2},
			},
			{
				in:  []byte{0, 0, 0, 0, 0},
				out: []byte{0, 0, 3, 0, 0, 3, 0},
			},
			{
				in:  []byte{0, 0, 0, 0, 5, 0},
				out: []byte{0, 0, 3, 0, 0, 5, 0},
			},
		}
		for _, tc := range testCases {
			buf := bytes.Buffer{}
			w := bits.NewEBSPWriter(&buf)
			for _, b := range tc.in {
				w.Write(uint(b), 8)
			}
			diff := deep.Equal(buf.Bytes(), tc.out)
			if diff != nil {
				t.Errorf("Got %v but wanted %d", buf.Bytes(), tc.out)
			}
		}
	})
	t.Run("write exp golomb", func(t *testing.T) {
		cases := []struct {
			bits string
			n    uint
		}{
			{"1", 0},
			{"010", 1},
			{"011", 2},
			{"00100", 3},
			{"0001111", 14},
			{"000010000", 15},
			{"000011111", 30},
		}

		for _, tc := range cases {
			b := bytes.Buffer{}
			w := bits.NewEBSPWriter(&b)
			w.WriteExpGolomb(tc.n)
			gotBits := getBitsWritten(w, &b)
			if gotBits != tc.bits {
				t.Errorf("wanted %s but got %s for %d", tc.bits, gotBits, tc.n)
			}
			nrBitsInBuffer := w.NrBitsInBuffer()
			if int(nrBitsInBuffer) != len(tc.bits)%8 {
				t.Errorf("wanted %d bits in buffer but got %d", len(tc.bits)%8, nrBitsInBuffer)
			}
			if w.AccError() != nil {
				t.Errorf("unexpected error: %v", w.AccError())
			}
		}
	})

	t.Run("write to limited writer", func(t *testing.T) {
		lw := newLimitedWriter(3)
		w := bits.NewEBSPWriter(lw)
		w.Write(0, 16)
		if lw.nrWritten != 2 {
			t.Errorf("wanted 2 bytes written but got %d", lw.nrWritten)
		}
		if w.AccError() != nil {
			t.Errorf("unexpected error: %v", w.AccError())
		}
		w.Write(1, 8)
		// Now we should have written 4 due to start code emulation prevention byte
		if lw.nrWritten != 4 {
			t.Errorf("wanted 4 bytes written but got %d", lw.nrWritten)
		}
		if w.AccError() == nil {
			t.Errorf("wanted error but got nil")
		}
		w.Write(1, 8)
		if w.AccError() == nil {
			t.Errorf("error should stay")
		}
		if lw.nrWritten != 4 {
			t.Errorf("wanted 4 bytes written but got %d", lw.nrWritten)
		}
	})

	t.Run("start code emulation prevention error", func(t *testing.T) {
		lw := newLimitedWriter(2)
		w := bits.NewEBSPWriter(lw)
		w.Write(0, 16)
		if lw.nrWritten != 2 {
			t.Errorf("wanted 2 bytes written but got %d", lw.nrWritten)
		}
		if w.AccError() != nil {
			t.Errorf("unexpected error: %v", w.AccError())
		}
		w.Write(1, 8)
		// Now we should have written 3 since start-code emulation triggered error
		if lw.nrWritten != 3 {
			t.Errorf("wanted 3 bytes written but got %d", lw.nrWritten)
		}
		if w.AccError() == nil {
			t.Errorf("wanted error but got nil")
		}
	})

	t.Run("write SEI and RBSP", func(t *testing.T) {
		b := bytes.Buffer{}
		w := bits.NewEBSPWriter(&b)
		w.WriteSEIValue(300)
		w.WriteRbspTrailingBits()
		gotBits := getBitsWritten(w, &b)
		expectedBits := "111111110010110110000000"
		if gotBits != expectedBits {
			t.Errorf("wanted %s but got %s", expectedBits, gotBits)

		}
	})
}

func getBitsWritten(w *bits.EBSPWriter, b *bytes.Buffer) string {
	bits := ""
	for _, c := range b.Bytes() {
		bits += fmt.Sprintf("%08b", c)
	}
	valueInWriter, nrBitsInWriter := w.BitsInBuffer()
	if nrBitsInWriter > 0 {
		fullByte := fmt.Sprintf("%08b", valueInWriter)
		bits += fullByte[8-nrBitsInWriter:]
	}
	return bits

}

type limitedWriter struct {
	nrWritten  uint
	maxNrBytes uint
}

func newLimitedWriter(maxNrBytes uint) *limitedWriter {
	return &limitedWriter{nrWritten: 0, maxNrBytes: maxNrBytes}
}

func (w *limitedWriter) Write(p []byte) (n int, err error) {
	prevNrWritten := w.nrWritten
	w.nrWritten += uint(len(p))
	if w.nrWritten > w.maxNrBytes {
		n = int(w.maxNrBytes - prevNrWritten)
		if n < 0 {
			n = 0
		}
		return n, fmt.Errorf("write limit reached")
	}
	return len(p), nil
}
