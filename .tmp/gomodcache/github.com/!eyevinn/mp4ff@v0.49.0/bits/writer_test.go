package bits_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/Eyevinn/mp4ff/bits"
)

func TestWriter(t *testing.T) {
	cases := []struct {
		inputs []uint
		want   []byte
		size   int
	}{
		{[]uint{255}, []byte{0xff}, 8},
		{[]uint{15, 15}, []byte{0xff}, 4},
		{[]uint{3, 3, 3, 3}, []byte{0xff}, 2},
		{[]uint{1, 1, 1, 1, 1, 1, 1, 1}, []byte{0xff}, 1},

		{[]uint{15, 15, 15}, []byte{0xff, 0xf0}, 4},
		{[]uint{3, 3, 3, 3, 3, 3}, []byte{0xff, 0xf0}, 2},
	}

	for _, tc := range cases {
		var buf bytes.Buffer
		writer := bits.NewWriter(&buf)

		for _, input := range tc.inputs {
			writer.Write(input, tc.size)
		}
		err := writer.AccError()
		if err != nil {
			t.Fatalf("Write should not fail: %s", err)
		}

		writer.Flush()
		err = writer.AccError()
		if err != nil {
			t.Fatalf("Flush should not fail: %s", err)
		}

		if !bytes.Equal(buf.Bytes(), tc.want) {
			t.Errorf("Write writes %x, want %x", buf.Bytes(), tc.want)
		}
	}
}

func TestMask(t *testing.T) {
	cases := []struct {
		want  string
		input int
	}{
		{"11111111", 8},
		{"00001111", 4},
		{"00000011", 2},
	}

	for _, tc := range cases {
		m := bits.Mask(tc.input)
		if got := fmt.Sprintf("%08b", m); got != tc.want {
			t.Errorf("mask(%d)=%s,want=%s", tc.input, got, tc.want)
		}
	}
}
