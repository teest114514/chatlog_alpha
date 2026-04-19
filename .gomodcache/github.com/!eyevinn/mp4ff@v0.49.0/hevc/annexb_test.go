package hevc

import (
	"testing"

	"github.com/go-test/deep"
)

func TestGetParameterSetsFromByteStream(t *testing.T) {
	testCases := []struct {
		name      string
		input     []byte
		wantedVPS [][]byte
		wantedSPS [][]byte
		wantedPPS [][]byte
	}{
		{
			"Only IDR",
			[]byte{0, 0, 0, 1, byte(NALU_IDR_W_RADL) << 1, 0, 0},
			nil, nil, nil,
		},
		{
			"AUD, VPS, SPS, PPS, IDR",
			[]byte{0, 0, 0, 1, byte(NALU_AUD) << 1, 2, 0,
				0, 0, 0, 1, byte(NALU_VPS) << 1, 5, 4,
				0, 0, 0, 1, byte(NALU_SPS) << 1, 7, 8,
				0, 0, 0, 1, byte(NALU_PPS) << 1, 1, 2,
				0, 0, 0, 1, byte(NALU_IDR_W_RADL) << 1, 0},
			[][]byte{{byte(NALU_VPS) << 1, 5, 4}},
			[][]byte{{byte(NALU_SPS) << 1, 7, 8}},
			[][]byte{{byte(NALU_PPS) << 1, 1, 2}},
		},
	}

	for _, tc := range testCases {
		gotVPS, gotSPS, gotPPS := GetParameterSetsFromByteStream(tc.input)
		if diff := deep.Equal(gotVPS, tc.wantedVPS); diff != nil {
			t.Errorf("%s: %v", tc.name, diff)
		}
		if diff := deep.Equal(gotSPS, tc.wantedSPS); diff != nil {
			t.Errorf("%s: %v", tc.name, diff)
		}
		if diff := deep.Equal(gotPPS, tc.wantedPPS); diff != nil {
			t.Errorf("%s: %v", tc.name, diff)
		}
	}
}

func TestExtractNalusOfTypeFromByteStream(t *testing.T) {
	testCases := []struct {
		name        string
		input       []byte
		naluType    NaluType
		beyondVideo bool
		nrWanted    int
	}{
		{
			"Only IDR. Search PPS",
			[]byte{0, 0, 0, 1, byte(NALU_IDR_W_RADL) << 1, 0, 1, 1, 1, 1},
			NALU_PPS,
			true,
			0,
		},
		{
			"Only IDR, excl video",
			[]byte{0, 0, 0, 1, byte(NALU_IDR_W_RADL) << 1, 0, 1, 1, 1, 1, 1},
			NALU_IDR_W_RADL,
			true,
			0,
		},
		{
			"Only IDR, incl video",
			[]byte{0, 0, 0, 1, byte(NALU_IDR_W_RADL) << 1, 0, 1, 1, 1, 1, 1},
			NALU_IDR_W_RADL,
			false,
			1,
		},
		{
			"AUD, SPS, PPS, IDR",
			[]byte{0, 0, 0, 1, byte(NALU_AUD) << 1, 2, 0,
				0, 0, 0, 1, byte(NALU_VPS) << 1, 5, 4,
				0, 0, 0, 1, byte(NALU_SPS) << 1, 1, 2,
				0, 0, 0, 1, byte(NALU_PPS) << 1, 5, 0,
				0, 0, 0, 1, byte(NALU_IDR_W_RADL) << 1, 0,
				1, 1, 1, 1, 1, 1},
			NALU_PPS,
			false,
			1,
		},
	}

	for _, tc := range testCases {
		nrNalus := ExtractNalusOfTypeFromByteStream(tc.naluType, tc.input, tc.beyondVideo)
		if len(nrNalus) != tc.nrWanted {
			t.Errorf("%q: got %d, wanted %d", tc.name, len(nrNalus), tc.nrWanted)
		}
	}
}
