package lz4_test

import (
	"bytes"
	"io"
	"io/ioutil"
	"testing"

	"github.com/pierrec/lz4/v4"
	"github.com/pierrec/lz4/v4/internal/lz4block"
)

func BenchmarkCompress(b *testing.B) {
	buf := make([]byte, len(pg1661))
	var c lz4.Compressor

	n, _ := c.CompressBlock(pg1661, buf)

	b.ReportAllocs()
	b.ResetTimer()
	b.ReportMetric(float64(n), "outbytes")

	for i := 0; i < b.N; i++ {
		_, _ = c.CompressBlock(pg1661, buf)
	}
}

func BenchmarkCompressRandom(b *testing.B) {
	buf := make([]byte, lz4.CompressBlockBound(len(random)))
	var c lz4.Compressor

	n, _ := c.CompressBlock(random, buf)

	b.ReportAllocs()
	b.SetBytes(int64(len(random)))
	b.ResetTimer()
	b.ReportMetric(float64(n), "outbytes")

	for i := 0; i < b.N; i++ {
		_, _ = c.CompressBlock(random, buf)
	}
}

func BenchmarkCompressHC(b *testing.B) {
	buf := make([]byte, len(pg1661))
	c := lz4.CompressorHC{Level: 16}

	n, _ := c.CompressBlock(pg1661, buf)

	b.ReportAllocs()
	b.ResetTimer()
	b.ReportMetric(float64(n), "outbytes")

	for i := 0; i < b.N; i++ {
		_, _ = c.CompressBlock(pg1661, buf)
	}
}

func BenchmarkUncompress(b *testing.B) {
	buf := make([]byte, len(pg1661))

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = lz4block.UncompressBlock(pg1661LZ4, buf, nil)
	}
}

func mustLoadFile(f string) []byte {
	b, err := ioutil.ReadFile(f)
	if err != nil {
		panic(err)
	}
	return b
}

var (
	pg1661    = mustLoadFile("testdata/pg1661.txt")
	digits    = mustLoadFile("testdata/e.txt")
	twain     = mustLoadFile("testdata/Mark.Twain-Tom.Sawyer.txt")
	random    = mustLoadFile("testdata/random.data")
	pg1661LZ4 = mustLoadFile("testdata/pg1661.txt.lz4")
	digitsLZ4 = mustLoadFile("testdata/e.txt.lz4")
	twainLZ4  = mustLoadFile("testdata/Mark.Twain-Tom.Sawyer.txt.lz4")
	randomLZ4 = mustLoadFile("testdata/random.data.lz4")
)

func benchmarkUncompress(b *testing.B, compressed []byte) {
	r := bytes.NewReader(compressed)
	zr := lz4.NewReader(r)

	// Decompress once to determine the uncompressed size of testfile.
	_, err := io.Copy(ioutil.Discard, zr)
	if err != nil {
		b.Fatal(err)
	}

	b.SetBytes(int64(len(compressed)))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		r.Reset(compressed)
		zr.Reset(r)
		_, _ = io.Copy(ioutil.Discard, zr)
	}
}

func BenchmarkUncompressPg1661(b *testing.B) { benchmarkUncompress(b, pg1661LZ4) }
func BenchmarkUncompressDigits(b *testing.B) { benchmarkUncompress(b, digitsLZ4) }
func BenchmarkUncompressTwain(b *testing.B)  { benchmarkUncompress(b, twainLZ4) }
func BenchmarkUncompressRand(b *testing.B)   { benchmarkUncompress(b, randomLZ4) }

func benchmarkCompress(b *testing.B, uncompressed []byte) {
	w := bytes.NewBuffer(nil)
	zw := lz4.NewWriter(w)
	r := bytes.NewReader(uncompressed)

	// Compress once to determine the compressed size of testfile.
	_, err := io.Copy(zw, r)
	if err != nil {
		b.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		b.Fatal(err)
	}

	b.SetBytes(int64(len(uncompressed)))
	b.ReportAllocs()
	b.ResetTimer()
	b.ReportMetric(float64(w.Len()), "outbytes")

	for i := 0; i < b.N; i++ {
		r.Reset(uncompressed)
		zw.Reset(w)
		_, _ = io.Copy(zw, r)
	}
}

func BenchmarkCompressPg1661(b *testing.B) { benchmarkCompress(b, pg1661) }
func BenchmarkCompressDigits(b *testing.B) { benchmarkCompress(b, digits) }
func BenchmarkCompressTwain(b *testing.B)  { benchmarkCompress(b, twain) }
func BenchmarkCompressRand(b *testing.B)   { benchmarkCompress(b, random) }

// Benchmark to check reallocations upon Reset().
// See issue https://github.com/pierrec/lz4/issues/52.
func BenchmarkWriterReset(b *testing.B) {
	b.ReportAllocs()

	zw := lz4.NewWriter(nil)
	src := mustLoadFile("testdata/gettysburg.txt")
	var buf bytes.Buffer

	for n := 0; n < b.N; n++ {
		buf.Reset()
		zw.Reset(&buf)

		_, _ = zw.Write(src)
		_ = zw.Close()
	}
}
