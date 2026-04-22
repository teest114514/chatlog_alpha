package mp4_test

import (
	"testing"

	"github.com/Eyevinn/mp4ff/mp4"
	"github.com/go-test/deep"
)

func TestSampleFlags(t *testing.T) {
	sf := mp4.SampleFlags{
		IsLeading:                 1,
		SampleDependsOn:           2,
		SampleIsDependedOn:        1,
		SampleHasRedundancy:       3,
		SamplePaddingValue:        5,
		SampleIsNonSync:           true,
		SampleDegradationPriority: 42,
	}

	sfBin := sf.Encode()
	sfDec := mp4.DecodeSampleFlags(sfBin)
	diff := deep.Equal(sfDec, sf)
	if diff != nil {
		t.Error(diff)
	}
}
