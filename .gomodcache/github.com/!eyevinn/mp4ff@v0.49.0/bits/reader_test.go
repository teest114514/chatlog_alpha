package bits_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/Eyevinn/mp4ff/bits"
)

func TestAccErrReader(t *testing.T) {
	t.Run("Read bits", func(t *testing.T) {
		input := []byte{0xff, 0x0f} // 1111 1111 0000 1111
		rd := bytes.NewReader(input)
		reader := bits.NewReader(rd)

		cases := []struct {
			readNrBits  int
			want        uint
			nrBytesRead int
			nrBitsRead  int
		}{
			{2, 3, 1, 2},   // 11
			{3, 7, 1, 5},   // 111
			{5, 28, 2, 10}, // 11100
			{3, 1, 2, 13},  // 001
			{3, 7, 2, 16},  // 111
		}

		for _, tc := range cases {
			got := reader.Read(tc.readNrBits)

			if got != tc.want {
				t.Errorf("Read(%d)=%b, want=%b", tc.readNrBits, got, tc.want)
			}
			if reader.NrBytesRead() != tc.nrBytesRead {
				t.Errorf("NrBytesRead()=%d, want=%d", reader.NrBytesRead(), tc.nrBytesRead)
			}
			if reader.NrBitsRead() != tc.nrBitsRead {
				t.Errorf("NrBitsRead()=%d, want=%d", reader.NrBitsRead(), tc.nrBitsRead)
			}
		}
		err := reader.AccError()
		if err != nil {
			t.Errorf("Got accumulated error: %s", err.Error())
		}
	})
	t.Run("Read signed bits", func(t *testing.T) {
		input := []byte{0xff, 0x0f} // 1111 1111 0000 1111
		rd := bytes.NewReader(input)
		reader := bits.NewReader(rd)

		cases := []struct {
			n    int
			want uint
		}{
			{2, 3},  // 11
			{3, 7},  // 111
			{5, 28}, // 11100
			{3, 1},  // 001
			{3, 7},  // 111
		}

		for _, tc := range cases {
			got := reader.Read(tc.n)

			if got != tc.want {
				t.Errorf("Read(%d)=%b, want=%b", tc.n, got, tc.want)
			}
		}
		err := reader.AccError()
		if err != nil {
			t.Errorf("Got accumulated error: %s", err.Error())
		}
	})
	t.Run("Read remaining bytes", func(t *testing.T) {
		input := []byte{0xef, 0x0f} // 1110 1111 0000 1111
		rd := bytes.NewReader(input)
		r := bits.NewReader(rd)
		gotRemaining := r.ReadRemainingBytes()
		if !bytes.Equal(gotRemaining, input) {
			t.Errorf("ReadRemainingBytes()=%b, want=%b", gotRemaining, input)
		}
		// Next check with non-bytealigned status
		rd = bytes.NewReader(input)
		r = bits.NewReader(rd)
		_ = r.ReadFlag()
		_ = r.ReadRemainingBytes()
		err := r.AccError()
		if err == nil {
			t.Errorf("Expected error due to not byte-aligned, but got nil")
		}
	})

	t.Run("Read flags", func(t *testing.T) {
		input := []byte{0xe5} // 1110 0101
		rd := bytes.NewReader(input)
		r := bits.NewReader(rd)
		for i := 0; i < 8; i++ {
			expectedValue := (input[0] >> (7 - i) & 1) > 0
			gotFlag := r.ReadFlag()
			if gotFlag != expectedValue {
				t.Errorf("Read flag %t, but wanted %t, case %d", gotFlag, expectedValue, i)
			}
		}
		_ = r.ReadFlag()
		wantedError := io.EOF
		if err := r.AccError(); err != wantedError {
			t.Errorf("wanted error %s, got %s", wantedError, err.Error())
		}
	})
}

func TestAccErrReaderSigned(t *testing.T) {
	input := []byte{0xff, 0x0c} // 1111 1111 0000 1100
	rd := bytes.NewReader(input)
	reader := bits.NewReader(rd)

	cases := []struct {
		readNrBits int
		want       int
	}{
		{2, -1}, // 11
		{3, -1}, // 111
		{5, -4}, // 11100
		{3, 1},  // 001
		{3, -4}, // 100
	}

	for _, tc := range cases {
		got := reader.ReadSigned(tc.readNrBits)

		if got != tc.want {
			t.Errorf("Read(%d)=%b, want=%b", tc.readNrBits, got, tc.want)
		}
	}
	err := reader.AccError()
	if err != nil {
		t.Errorf("Got accumulated error: %s", err.Error())
	}
}

func TestBadAccErrReader(t *testing.T) {
	// Check that reading beyond EOF provides value = 0 after acc error
	input := []byte{0xff, 0x0f} // 1111 1111 0000 1111
	rd := bytes.NewReader(input)
	reader := bits.NewReader(rd)

	cases := []struct {
		err  error
		n    int
		want uint
	}{
		{nil, 2, 3},     // 11
		{nil, 3, 7},     // 111
		{io.EOF, 12, 0}, // 0 because of error
		{io.EOF, 3, 0},  // 0 because of acc error
		{io.EOF, 3, 0},  // 0 because of acc error
	}

	for _, tc := range cases {
		got := reader.Read(tc.n)

		if got != tc.want {
			t.Errorf("Read(%d)=%b, want=%b", tc.n, got, tc.want)
		}
	}
	err := reader.AccError()
	if err != io.EOF {
		t.Errorf("Wanted io.EOF but got %v", err)
	}
}
