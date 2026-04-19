package bits_test

import (
	"testing"

	"github.com/Eyevinn/mp4ff/bits"
)

func TestCeilLog2(t *testing.T) {
	testCases := []struct {
		n    uint
		want int
	}{
		{0, 0},
		{1, 0},
		{2, 1},
		{3, 2},
		{4, 2},
		{5, 3},
		{128, 7},
	}
	for _, tc := range testCases {
		if got := bits.CeilLog2(tc.n); got != tc.want {
			t.Errorf("CeilLog2(%d) = %d, want %d", tc.n, got, tc.want)
		}
	}
}
