package bits_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"testing"

	"github.com/Eyevinn/mp4ff/bits"
	"github.com/go-test/deep"
)

func TestEBSPReader(t *testing.T) {
	t.Run("read bits", func(t *testing.T) {
		testCases := []struct {
			name                            string
			hexData                         string
			readBits                        int
			expectedValue                   uint
			expectedNrBytesRead             int
			expectedNrBitsRead              int
			expectedNrBitsReadInCurrentByte int
			expectedError                   string
		}{
			{"zero bits", "00", 0, 0, 0, 0, 8, ""},
			{"1 bit", "0001", 1, 0, 1, 1, 1, ""},
			{"8 bits", "0001", 8, 0x00, 1, 8, 8, ""},
			{"12 bits", "0010", 12, 0x001, 2, 12, 4, ""},
			{"16 bits", "0102", 16, 0x0102, 2, 16, 8, ""},
			{"24 bits including start code emulation", "00000304", 24, 0x000004, 4, 32, 8, ""},
			{"missing data after start code emulation prevention byte", "000003", 17, 0, 0, 0, 0, "EOF"},
		}
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				data, err := hex.DecodeString(tc.hexData)
				if err != nil {
					t.Error(err)
				}
				buf := bytes.NewBuffer(data)
				r := bits.NewEBSPReader(buf)
				if r.AccError() != nil {
					t.Errorf("expected no error, got %v", r.AccError())
				}
				v := r.Read(tc.readBits)
				if tc.expectedError != "" {
					gotErr := r.AccError().Error()
					if r.AccError().Error() != tc.expectedError {
						t.Errorf("expected error %s, got %s", tc.expectedError, gotErr)
					}
					return
				}
				if v != tc.expectedValue {
					t.Errorf("expected value %d, got %d", tc.expectedValue, v)
				}
				if r.NrBytesRead() != tc.expectedNrBytesRead {
					t.Errorf("expected %d bytes read, got %d", tc.expectedNrBytesRead, r.NrBytesRead())
				}
				if r.NrBitsRead() != tc.expectedNrBitsRead {
					t.Errorf("expected %d bits read, got %d", tc.expectedNrBitsRead, r.NrBitsRead())
				}
				if r.NrBitsReadInCurrentByte() != tc.expectedNrBitsReadInCurrentByte {
					t.Errorf("expected %d bits read in current byte, got %d", tc.expectedNrBitsReadInCurrentByte,
						r.NrBitsReadInCurrentByte())
				}
			})
		}
	})
	t.Run("read bytes", func(t *testing.T) {
		testCases := []struct {
			name          string
			hexData       string
			readNrBytes   int
			expectedValue []byte
			expectedError string
		}{
			{"1 byte", "01", 1, []byte{0x01}, ""},
			{"too many bytes", "01", 2, nil, "EOF"},
		}
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				data, err := hex.DecodeString(tc.hexData)
				if err != nil {
					t.Error(err)
				}
				buf := bytes.NewBuffer(data)
				r := bits.NewEBSPReader(buf)
				got := r.ReadBytes(tc.readNrBytes)
				err = r.AccError()
				if tc.expectedError != "" {
					if err == nil {
						t.Errorf("expected error %s, got none", tc.expectedError)
					} else {
						if err.Error() != tc.expectedError {
							t.Errorf("expected error %s, got %s", tc.expectedError, err.Error())
						}
					}
				} else {
					if !bytes.Equal(got, tc.expectedValue) {
						t.Errorf("expected %v, got %v", tc.expectedValue, got)
					}
				}
			})
		}
	})
	t.Run("read exp golomb", func(t *testing.T) {
		cases := []struct {
			input       uint
			wanted      uint
			expectError bool
		}{
			{0b10000000, 0, false},
			{0b01000000, 1, false},
			{0b01100000, 2, false},
			{0b00010000, 7, false},
			{0b00010010, 8, false},
			{0b00011110, 14, false},
			{0x00, 0, true},
		}
		for _, c := range cases {
			buf := bytes.NewBuffer([]byte{byte(c.input)})
			r := bits.NewEBSPReader(buf)
			got := r.ReadExpGolomb()
			if c.expectError && r.AccError() == nil {
				t.Errorf("expected error, got none")
				_ = r.ReadExpGolomb()
				if r.AccError() == nil {
					t.Errorf("expected error to stay")
				}
			} else {
				if got != c.wanted {
					t.Errorf("got %d, wanted %d", got, c.wanted)
				}
			}
		}
	})
	t.Run("read signed exp golomb", func(t *testing.T) {
		cases := []struct {
			input       uint
			wanted      int
			expectError bool
		}{
			{0b10000000, 0, false},
			{0b01000000, 1, false},
			{0b01100000, -1, false},
			{0b00010000, 4, false},
			{0b00010010, -4, false},
			{0b00011110, -7, false},
			{0x00, 0, true},
		}
		for _, c := range cases {
			buf := bytes.NewBuffer([]byte{byte(c.input)})
			r := bits.NewEBSPReader(buf)
			got := r.ReadSignedGolomb()
			if c.expectError && r.AccError() == nil {
				t.Errorf("expected error, got none")
				_ = r.ReadSignedGolomb()
				if r.AccError() == nil {
					t.Errorf("expected error to stay")
				}
			} else {
				if got != c.wanted {
					t.Errorf("got %d, wanted %d", got, c.wanted)
				}
			}
		}
	})
	t.Run("remove escape bytes", func(t *testing.T) {

		cases := []struct{ name, start, want string }{
			{
				"read last byte",
				"32",
				"32",
			},
			{
				"remove escape but not 007",
				"27640020ac2ec05005bb011000000300100000078e840016e300005b8d8bdef83b438627",
				"27640020ac2ec05005bb0110000000100000078e840016e300005b8d8bdef83b438627",
			},
			{
				"Long zero sequence",
				"00000300000300",
				"0000000000",
			},
		}

		for _, c := range cases {
			byteData, _ := hex.DecodeString(c.start)
			buf := bytes.NewBuffer(byteData)
			r := bits.NewEBSPReader(buf)
			got := []byte{}
			for {
				b := r.Read(8)
				if r.AccError() == io.EOF {
					break
				}
				got = append(got, byte(b))
			}
			wantBytes, err := hex.DecodeString(c.want)
			if err != nil {
				t.Error(err)
			}
			if diff := deep.Equal(got, wantBytes); diff != nil {
				t.Errorf("%s: %v", c.name, diff)
			}
		}
	})
	t.Run("get precise position", func(t *testing.T) {
		testCases := []struct {
			name             string
			inBytes          []byte
			nrBitsToRead     int
			nrBytesRead      int
			nrBitsReadInByte int
		}{
			{
				name:             "Read 13 bits",
				inBytes:          []byte{0, 1, 2},
				nrBitsToRead:     13,
				nrBytesRead:      2,
				nrBitsReadInByte: 5,
			},
		}

		for _, c := range testCases {
			t.Run(c.name, func(t *testing.T) {
				buf := bytes.NewBuffer(c.inBytes)
				r := bits.NewEBSPReader(buf)
				_ = r.Read(c.nrBitsToRead)
				if r.AccError() != nil {
					t.Error(r.AccError())
				}
				if r.NrBytesRead() != c.nrBytesRead {
					t.Errorf("%s: got %d bytes want %d bytes", c.name, r.NrBytesRead(), c.nrBytesRead)
				}
				if r.NrBitsReadInCurrentByte() != c.nrBitsReadInByte {
					t.Errorf("%s: got %d bits want %d bits", c.name, r.NrBitsReadInCurrentByte(), c.nrBitsReadInByte)
				}
			})
		}
	})
	t.Run("more rbsp data", func(t *testing.T) {

		testCases := []struct {
			name         string
			inBytes      []byte
			nrBitsBefore int
			moreRbsp     bool
			nrBitsAfter  int
			valueRead    uint
		}{
			{
				name:         "start of byte",
				inBytes:      []byte{0b10000000},
				nrBitsBefore: 0,
				moreRbsp:     false,
				nrBitsAfter:  0,
				valueRead:    0,
			},
			{
				name:         "one bit left",
				inBytes:      []byte{0b11000000},
				nrBitsBefore: 0,
				moreRbsp:     true,
				nrBitsAfter:  2,
				valueRead:    3,
			},
			{
				name:         "after one bit",
				inBytes:      []byte{0b11000000},
				nrBitsBefore: 1,
				moreRbsp:     false,
				nrBitsAfter:  0,
				valueRead:    0,
			},
			{
				name:         "after one byte",
				inBytes:      []byte{0b11110111, 0b11001000},
				nrBitsBefore: 9,
				moreRbsp:     true,
				nrBitsAfter:  4,
				valueRead:    0b00001001,
			},
		}

		for _, c := range testCases {
			t.Run(c.name, func(t *testing.T) {
				brd := bytes.NewReader(c.inBytes)
				r := bits.NewEBSPReader(brd)
				_ = r.Read(c.nrBitsBefore)
				if r.AccError() != nil {
					t.Error(r.AccError())
				}
				moreRbsp, err := r.MoreRbspData()
				if err != nil {
					t.Error(err)
				}
				if moreRbsp != c.moreRbsp {
					t.Errorf("%s: got %t want %t", c.name, moreRbsp, c.moreRbsp)
				}
				got := r.Read(c.nrBitsAfter)
				if r.AccError() != nil {
					t.Error(r.AccError())
				}
				if got != c.valueRead {
					t.Errorf("%s: got %d want %d after check", c.name, got, c.valueRead)
				}
			})
		}
	})
	t.Run("read traling RBSP bits", func(t *testing.T) {
		input := []byte{0b10000000}
		brd := bytes.NewReader(input)
		r := bits.NewEBSPReader(brd)
		err := r.ReadRbspTrailingBits()
		if err != nil {
			t.Error(err)
		}
		_ = r.Read(1)
		if r.AccError() != io.EOF {
			t.Errorf("Not at end after reading rbsp_trailing_bits")
		}
	})
	t.Run("read after earlier error", func(t *testing.T) {
		input := []byte{0b10000000}
		brd := bytes.NewReader(input)
		r := bits.NewEBSPReader(brd)
		r.SetError(io.ErrUnexpectedEOF)
		// Read shold never result in panic
		// Error should be preservedd
		_ = r.Read(100)
		if r.AccError() != io.ErrUnexpectedEOF {
			t.Errorf("Expected error not found")
		}
		_ = r.ReadBytes(100)
		if r.AccError() != io.ErrUnexpectedEOF {
			t.Errorf("Expected error not found")
		}
		_ = r.ReadExpGolomb()
		if r.AccError() != io.ErrUnexpectedEOF {
			t.Errorf("Expected error not found")
		}
		_ = r.ReadSignedGolomb()
		if r.AccError() != io.ErrUnexpectedEOF {
			t.Errorf("Expected error not found")
		}
		_ = r.ReadRbspTrailingBits()
		if r.AccError() != io.ErrUnexpectedEOF {
			t.Errorf("Expected error not found")
		}
	})

	t.Run("try seek in non-seekable reader", func(t *testing.T) {
		emptyBuf := bytes.Buffer{}
		r := bits.NewEBSPReader(&emptyBuf)
		_, err := r.MoreRbspData()
		if !errors.Is(err, bits.ErrNotReadSeeker) {
			t.Error("Expected error checking for more data in empty buffer")
		}
	})

	t.Run("no rbsp bits left", func(t *testing.T) {
		input := []byte{0b1}
		brd := bytes.NewReader(input)
		r := bits.NewEBSPReader(brd)
		for i := 0; i < 8; i++ {
			_ = r.ReadFlag()
		}
		more, err := r.MoreRbspData()
		if more {
			t.Error("Expected no more rbsp data")
		}
		if err != nil {
			t.Error("Expected error to be nil when no more data")
		}
	})

	t.Run("not last rbsp bit bit", func(t *testing.T) {
		input := []byte{0b01000001}
		brd := bytes.NewReader(input)
		r := bits.NewEBSPReader(brd)
		more, err := r.MoreRbspData()
		if !more {
			t.Error("Expected more rbsp data")
		}
		if err != nil {
			t.Error("Expected error to be nil when no more data")
		}
		err = r.ReadRbspTrailingBits()
		if err == nil {
			t.Error("Expected error when reading trailing bits")
		}
		err = r.ReadRbspTrailingBits()
		if err == nil {
			t.Error("Expected error when reading trailing bits")
		}

	})

}
