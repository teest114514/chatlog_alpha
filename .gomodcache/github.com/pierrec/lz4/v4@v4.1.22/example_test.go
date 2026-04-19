package lz4_test

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/pierrec/lz4/v4"
)

func Example() {
	// Compress and uncompress an input string.
	s := "hello world"
	r := strings.NewReader(s)

	// The pipe will uncompress the data from the writer.
	pr, pw := io.Pipe()
	zw := lz4.NewWriter(pw)
	zr := lz4.NewReader(pr)

	go func() {
		// Compress the input string.
		_, _ = io.Copy(zw, r)
		_ = zw.Close() // Make sure the writer is closed
		_ = pw.Close() // Terminate the pipe
	}()

	_, _ = io.Copy(os.Stdout, zr)

	// Output:
	// hello world
}

func ExampleCompressBlock() {
	s := "hello world"
	data := []byte(strings.Repeat(s, 100))
	buf := make([]byte, lz4.CompressBlockBound(len(data)))

	var c lz4.Compressor
	n, err := c.CompressBlock(data, buf)
	if err != nil {
		fmt.Println(err)
	}
	if n >= len(data) {
		fmt.Printf("`%s` is not compressible", s)
	}
	buf = buf[:n] // compressed data

	// Allocate a very large buffer for decompression.
	out := make([]byte, 10*len(data))
	n, err = lz4.UncompressBlock(buf, out)
	if err != nil {
		fmt.Println(err)
	}
	out = out[:n] // uncompressed data

	fmt.Println(string(out[:len(s)]))

	// Output:
	// hello world
}
