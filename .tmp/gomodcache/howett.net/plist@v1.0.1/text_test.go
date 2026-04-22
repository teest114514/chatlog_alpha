package plist

import (
	"bytes"
	"io/ioutil"
	"testing"
)

func BenchmarkOpenStepGenerate(b *testing.B) {
	for i := 0; i < b.N; i++ {
		d := newTextPlistGenerator(ioutil.Discard, OpenStepFormat)
		d.generateDocument(plistValueTree)
	}
}

func BenchmarkOpenStepParse(b *testing.B) {
	buf := bytes.NewReader([]byte(plistValueTreeAsOpenStep))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StartTimer()
		d := newTextPlistParser(buf)
		d.parseDocument()
		b.StopTimer()
		buf.Seek(0, 0)
	}
}

func BenchmarkGNUStepParse(b *testing.B) {
	buf := bytes.NewReader([]byte(plistValueTreeAsGNUStep))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StartTimer()
		d := newTextPlistParser(buf)
		d.parseDocument()
		b.StopTimer()
		buf.Seek(0, 0)
	}
}

// The valid text test cases have been merged into the common/global test cases.
