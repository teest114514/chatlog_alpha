package lz4_test

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"strings"
	"testing"

	"github.com/pierrec/lz4/v4"
)

func TestCompressingReader(t *testing.T) {
	goldenFiles := []string{
		"testdata/e.txt",
		"testdata/gettysburg.txt",
		"testdata/Mark.Twain-Tom.Sawyer.txt",
		"testdata/Mark.Twain-Tom.Sawyer_long.txt",
		"testdata/pg1661.txt",
		"testdata/pi.txt",
		"testdata/random.data",
		"testdata/repeat.txt",
		"testdata/issue102.data",
	}

	for _, fname := range goldenFiles {
		for _, option := range []lz4.Option{
			lz4.BlockChecksumOption(true),
			lz4.SizeOption(123),
		} {
			label := fmt.Sprintf("%s/%s", fname, option)
			t.Run(label, func(t *testing.T) {
				fname := fname
				option := option
				t.Parallel()

				raw, err := ioutil.ReadFile(fname)
				if err != nil {
					t.Fatal(err)
				}
				r := ioutil.NopCloser(bytes.NewReader(raw))

				// Compress.
				zcomp := lz4.NewCompressingReader(r)
				if err := zcomp.Apply(option, lz4.CompressionLevelOption(lz4.Level1)); err != nil {
					t.Fatal(err)
				}

				zout, err := ioutil.ReadAll(zcomp)
				if err != nil {
					t.Fatal(err)
				}

				// Uncompress.
				zr := lz4.NewReader(bytes.NewReader(zout))
				out, err := ioutil.ReadAll(zr)
				if err != nil {
					t.Fatal(err)
				}

				// The uncompressed data must be the same as the initial input.
				if got, want := len(out), len(raw); got != want {
					t.Errorf("invalid sizes: got %d; want %d", got, want)
				}

				if !bytes.Equal(out, raw) {
					t.Fatal("uncompressed data does not match original")
				}

				if strings.Contains(option.String(), "SizeOption") {
					if got, want := zr.Size(), 123; got != want {
						t.Errorf("invalid sizes: got %d; want %d", got, want)
					}
				}
			})
		}
	}
}
