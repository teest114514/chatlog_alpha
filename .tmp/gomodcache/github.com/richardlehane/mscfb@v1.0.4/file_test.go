package mscfb

import (
	"testing"
)

func equal(a [][2]int64, b [][2]int64) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v[0] != b[i][0] || v[1] != b[i][1] {
			return false
		}
	}
	return true
}

func TestCompress(t *testing.T) {
	a := [][2]int64{[2]int64{4608, 1024}, [2]int64{5632, 1024}, [2]int64{6656, 1024}, [2]int64{7680, 1024}, [2]int64{8704, 1024}, [2]int64{9728, 1024}, [2]int64{10752, 512}}
	ar := [][2]int64{[2]int64{4608, 6656}}
	a = compressChain(a)
	if !equal(a, ar) {
		t.Errorf("Streams compress fail; Expecting: %v, Got: %v", ar, a)
	}
	b := [][2]int64{[2]int64{4608, 1024}, [2]int64{6656, 1024}, [2]int64{7680, 1024}, [2]int64{8704, 1024}, [2]int64{10752, 512}}
	br := [][2]int64{[2]int64{4608, 1024}, [2]int64{6656, 3072}, [2]int64{10752, 512}}
	b = compressChain(b)
	if !equal(b, br) {
		t.Errorf("Streams compress fail; Expecting: %v, Got: %v", br, b)
	}
}
