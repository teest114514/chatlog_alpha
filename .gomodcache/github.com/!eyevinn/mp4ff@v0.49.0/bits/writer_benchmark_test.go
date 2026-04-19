package bits_test

import (
	"io"
	"testing"

	"github.com/Eyevinn/mp4ff/bits"
)

func BenchmarkWrite(b *testing.B) {
	writer := bits.NewWriter(io.Discard)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		writer.Write(0xff, 8)
	}
	err := writer.AccError()
	if err != nil {
		b.Fatal(err)
	}
}

func BenchmarkEbspWrite(b *testing.B) {
	writer := bits.NewEBSPWriter(io.Discard)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		writer.Write(0xff, 8)
	}
}
