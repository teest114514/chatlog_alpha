package lz4_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/pierrec/lz4/v4"
)

func _o(s ...lz4.Option) []lz4.Option {
	return s
}

func TestReader(t *testing.T) {
	goldenFiles := []struct {
		name   string
		isText bool
	}{
		{
			name:   "testdata/e.txt.lz4",
			isText: true,
		},
		{
			name:   "testdata/gettysburg.txt.lz4",
			isText: true,
		},
		{
			name:   "testdata/Mark.Twain-Tom.Sawyer.txt.lz4",
			isText: true,
		},
		{
			name:   "testdata/Mark.Twain-Tom.Sawyer_long.txt.lz4",
			isText: true,
		},
		{
			name:   "testdata/Mark.Twain-Tom.Sawyer_linked.txt.lz4",
			isText: true,
		},
		{
			name:   "testdata/pg1661.txt.lz4",
			isText: false,
		},
		{
			name:   "testdata/pi.txt.lz4",
			isText: true,
		},
		{
			name:   "testdata/random.data.lz4",
			isText: false,
		},
		{
			name:   "testdata/repeat.txt.lz4",
			isText: true,
		},
		{
			name:   "testdata/pg_control.tar.lz4",
			isText: false,
		},
	}

	for _, golden := range goldenFiles {
		for _, opts := range [][]lz4.Option{
			nil,
			_o(lz4.ConcurrencyOption(-1)),
		} {
			fname := golden.name
			isText := golden.isText
			label := fmt.Sprintf("%s %v", fname, opts)
			t.Run(label, func(t *testing.T) {
				t.Parallel()

				f, err := os.Open(fname)
				if err != nil {
					t.Fatal(err)
				}
				defer f.Close()

				rawfile := strings.TrimSuffix(fname, ".lz4")
				_raw, err := ioutil.ReadFile(rawfile)
				if err != nil {
					t.Fatal(err)
				}
				var raw []byte
				if isText && runtime.GOOS == "windows" {
					raw = []byte(strings.ReplaceAll(string(_raw), "\r\n", "\n"))
				} else {
					raw = _raw
				}

				out := new(bytes.Buffer)
				zr := lz4.NewReader(f)
				if err := zr.Apply(opts...); err != nil {
					t.Fatal(err)
				}
				n, err := io.Copy(out, zr)
				if err != nil {
					t.Error(err)
				}

				if got, want := int(n), len(raw); got != want {
					t.Errorf("invalid size: got %d; want %d", got, want)
				}

				if got, want := out.Bytes(), raw; !reflect.DeepEqual(got, want) {
					t.Fatal("uncompressed data does not match original")
				}

				if len(raw) < 20 {
					return
				}

				f2, err := os.Open(fname)
				if err != nil {
					t.Fatal(err)
				}
				defer f2.Close()

				out.Reset()
				zr = lz4.NewReader(f2)
				_, err = io.CopyN(out, zr, 10)
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(out.Bytes(), raw[:10]) {
					t.Fatal("partial read does not match original")
				}
			})
		}
	}
}

func TestReader_Reset(t *testing.T) {
	data := pg1661LZ4
	buf := new(bytes.Buffer)
	src := bytes.NewReader(data)
	zr := lz4.NewReader(src)

	// Partial read.
	_, _ = io.CopyN(buf, zr, int64(len(data))/2)

	buf.Reset()
	src.Reset(data)
	// Another time to maybe trigger some edge case.
	src.Reset(data)
	zr.Reset(src)
	if _, err := io.Copy(buf, zr); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(buf.Bytes(), pg1661) {
		t.Fatal("result does not match original")
	}
}

type brokenWriter int

func (w *brokenWriter) Write(p []byte) (n int, err error) {
	n = len(p)
	if n > int(*w) {
		n = int(*w)
		err = errors.New("broken")
	}
	*w -= brokenWriter(n)
	return
}

// WriteTo should report the number of bytes successfully written,
// not the number successfully decompressed.
func TestWriteToBrokenWriter(t *testing.T) {
	const capacity = 10
	w := brokenWriter(capacity)
	r := lz4.NewReader(bytes.NewReader(pg1661LZ4))

	n, err := r.WriteTo(&w)
	switch {
	case n > capacity:
		t.Errorf("reported number of bytes written %d too big", n)
	case err == nil:
		t.Error("no error from broken Writer")
	case err.Error() != "broken":
		t.Errorf("unexpected error %q", err.Error())
	}
}

func TestReaderLegacy(t *testing.T) {
	goldenFiles := []string{
		"testdata/vmlinux_LZ4_19377.lz4",
		"testdata/bzImage_lz4_isolated.lz4",
	}

	for _, fname := range goldenFiles {
		for _, opts := range [][]lz4.Option{
			nil,
			_o(lz4.ConcurrencyOption(-1)),
		} {
			label := fmt.Sprintf("%s %v", fname, opts)
			t.Run(label, func(t *testing.T) {
				fname := fname
				t.Parallel()

				var out bytes.Buffer
				rawfile := strings.TrimSuffix(fname, ".lz4")
				raw, err := ioutil.ReadFile(rawfile)
				if err != nil {
					t.Fatal(err)
				}

				f, err := os.Open(fname)
				if err != nil {
					t.Fatal(err)
				}
				defer f.Close()

				zr := lz4.NewReader(f)
				if err := zr.Apply(opts...); err != nil {
					t.Fatal(err)
				}
				n, err := io.Copy(&out, zr)
				if err != nil {
					t.Fatal(err, n)
				}

				if got, want := int(n), len(raw); got != want {
					t.Errorf("invalid sizes: got %d; want %d", got, want)
				}

				if got, want := out.Bytes(), raw; !bytes.Equal(got, want) {
					t.Fatal("uncompressed data does not match original")
				}

				if len(raw) < 20 {
					return
				}

				f2, err := os.Open(fname)
				if err != nil {
					t.Fatal(err)
				}
				defer f2.Close()

				out.Reset()
				zr = lz4.NewReader(f2)
				_, err = io.CopyN(&out, zr, 10)
				if err != nil {
					t.Fatal(err)
				}

				if !bytes.Equal(out.Bytes(), raw[:10]) {
					t.Fatal("partial read does not match original")
				}

				out.Reset()
				_, err = io.CopyN(&out, zr, 10)
				if err != nil {
					t.Fatal(err)
				}

				if !bytes.Equal(out.Bytes(), raw[10:20]) {
					t.Fatal("after seek, partial read does not match original")
				}
			})
		}
	}
}

func TestUncompressBadBlock(t *testing.T) {
	f, err := os.Open("testdata/malformed.block.lz4")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr := lz4.NewReader(f)
	if err := zr.Apply(lz4.ConcurrencyOption(4)); err != nil {
		t.Fatal(err)
	}
	_, err = ioutil.ReadAll(zr)
	if err == nil || !strings.Contains(err.Error(), "invalid block checksum") {
		t.Error("bad block is not detected")
	}
}

func TestValidFrameHeader(t *testing.T) {
	for _, tt := range []struct {
		name    string
		inBytes []byte
		want    bool
		errNil  bool
	}{
		{
			name:    "It is a LZ4",
			inBytes: []byte{4, 34, 77, 24, 96, 112, 115, 113, 199, 14, 0, 194, 48, 55, 48, 55, 48, 49, 48, 48, 48, 48, 48, 48, 8, 0, 67, 52, 49, 101, 100, 16, 0, 12, 2, 0, 139, 49, 51, 53, 102, 48, 51, 56, 98, 23, 0, 15, 2, 0, 14, 20, 50, 33, 0, 41, 46, 0, 112, 0, 31, 50, 112, 0},
			want:    true,
			errNil:  true,
		},
		{
			name:    "Not a LZ4",
			inBytes: []byte("I am not a lz4 header"),
			want:    false,
			errNil:  true,
		},
		{
			name:    "It is a legacy lz4",
			inBytes: []byte{2, 33, 76, 24, 191, 4, 0, 0, 240, 18, 32, 32, 70, 111, 117, 114, 32, 115, 99, 111, 114, 101, 32, 97, 110, 100, 32, 115, 101, 118, 101, 110, 32, 121, 101, 97, 114, 115, 32, 97, 103, 111, 32, 30, 0, 240, 39, 102, 97, 116, 104, 101, 114, 115, 32, 98, 114, 111, 117, 103, 104, 116, 32, 102},
			want:    true,
			errNil:  true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := lz4.ValidFrameHeader(tt.inBytes)
			if err != nil {
				if tt.errNil {
					t.Errorf("ValidFrameHeader(bytes.NewReader(%v)) returned error %v, want nil", tt.inBytes, err)
				}
				return
			}
			if got != tt.want {
				t.Errorf("ValidFrameHeader(bytes.NewReader(%v)) returned %t, want %t", tt.inBytes, got, tt.want)
			}
		})
	}
}
