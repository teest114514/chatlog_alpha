package hevc

import (
	"strings"
	"testing"

	"github.com/go-test/deep"
)

func TestGetNaluTypes(t *testing.T) {
	testCases := []struct {
		name                string
		input               []byte
		wanted              []NaluType
		nalusUpToFirstVideo []NaluType
		containsVPS         bool
		isRapSample         bool
		isIDRSample         bool
	}{
		{
			"AUD",
			[]byte{0, 0, 0, 2, 70, 0},
			[]NaluType{NALU_AUD},
			[]NaluType{NALU_AUD},
			false,
			false,
			false,
		},
		{
			"AUD, VPS, SPS, PPS, and IDR ",
			[]byte{
				0, 0, 0, 2, 70, 2,
				0, 0, 0, 3, 64, 1, 1,
				0, 0, 0, 3, 66, 2, 2,
				0, 0, 0, 3, 68, 3, 3,
				0, 0, 0, 3, 40, 4, 4},
			[]NaluType{NALU_AUD, NALU_VPS, NALU_SPS, NALU_PPS, NALU_IDR_N_LP},
			[]NaluType{NALU_AUD, NALU_VPS, NALU_SPS, NALU_PPS, NALU_IDR_N_LP},
			true,
			true,
			true,
		},
		{
			"too short",
			[]byte{0, 0, 0},
			[]NaluType{},
			[]NaluType{},
			false,
			false,
			false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := FindNaluTypes(tc.input)
			if diff := deep.Equal(got, tc.wanted); diff != nil {
				t.Errorf("nalulist diff: %v", diff)
			}
			got = FindNaluTypesUpToFirstVideoNalu(tc.input)
			if diff := deep.Equal(got, tc.nalusUpToFirstVideo); diff != nil {
				t.Errorf("nalus before first video diff: %v", diff)
			}
			hasVPS := ContainsNaluType(tc.input, NALU_VPS)
			if hasVPS != tc.containsVPS {
				t.Errorf("got %t instead of %t", hasVPS, tc.containsVPS)
			}
			isRAP := IsRAPSample(tc.input)
			if isRAP != tc.isRapSample {
				t.Errorf("got %t instead of %t", isRAP, tc.isRapSample)
			}
			isIDR := IsIDRSample(tc.input)
			if isIDR != tc.isIDRSample {
				t.Errorf("got %t instead of %t", isIDR, tc.isIDRSample)
			}
		})
	}
}

func TestHasParameterSets(t *testing.T) {
	testCases := []struct {
		name   string
		input  []byte
		wanted bool
	}{
		{
			"AUD",
			[]byte{0, 0, 0, 2, 70, 0},
			false,
		},
		{
			"AUD, VPS, SPS, PPS, and IDR ",
			[]byte{
				0, 0, 0, 2, 70, 2,
				0, 0, 0, 3, 64, 1, 1,
				0, 0, 0, 3, 66, 2, 2,
				0, 0, 0, 3, 68, 3, 3,
				0, 0, 0, 3, 40, 4, 4},
			true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := HasParameterSets(tc.input)
			if got != tc.wanted {
				t.Errorf("got %t instead of %t", got, tc.wanted)
			}
		})
	}
}

func TestGetParameterSets(t *testing.T) {
	testCases := []struct {
		name      string
		input     []byte
		wantedVPS [][]byte
		wantedSPS [][]byte
		wantedPPS [][]byte
	}{
		{
			"AUD",
			[]byte{0, 0, 0, 2, 70, 0},
			nil, nil, nil,
		},
		{
			"AUD, VPS, SPS, PPS, and IDR ",
			[]byte{
				0, 0, 0, 2, 70, 2,
				0, 0, 0, 3, 64, 1, 1,
				0, 0, 0, 3, 66, 2, 2,
				0, 0, 0, 3, 68, 3, 3,
				0, 0, 0, 3, 40, 4, 4},
			[][]byte{{64, 1, 1}},
			[][]byte{{66, 2, 2}},
			[][]byte{{68, 3, 3}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			gotVPS, gotSPS, gotPPS := GetParameterSets(tc.input)
			if diff := deep.Equal(gotVPS, tc.wantedVPS); diff != nil {
				t.Errorf("VPS diff: %v", diff)
			}
			if diff := deep.Equal(gotSPS, tc.wantedSPS); diff != nil {
				t.Errorf("SPS diff: %v", diff)
			}
			if diff := deep.Equal(gotPPS, tc.wantedPPS); diff != nil {
				t.Errorf("PPS diff: %v", diff)
			}
		})
	}
}

func TestNaluTypeStrings(t *testing.T) {
	named := 0
	for n := NaluType(0); n < NaluType(64); n++ {
		desc := n.String()
		if !strings.HasPrefix(desc, "Other") {
			named++
		}
	}
	if named != 22 {
		t.Errorf("got %d named instead of 22", named)
	}
}

func TestIsVideoNaluType(t *testing.T) {
	testCases := []struct {
		name     string
		naluType NaluType
		want     bool
	}{
		{
			name:     "video type - NALU_TRAIL_N (0)",
			naluType: NALU_TRAIL_N,
			want:     true,
		},
		{
			name:     "video type - NALU_TRAIL_R (1)",
			naluType: NALU_TRAIL_R,
			want:     true,
		},
		{
			name:     "video type - NALU_IDR_W_RADL (19)",
			naluType: NALU_IDR_W_RADL,
			want:     true,
		},
		{
			name:     "video type - highest (31)",
			naluType: 31,
			want:     true,
		},
		{
			name:     "non-video type - VPS (32)",
			naluType: NALU_VPS,
			want:     false,
		},
		{
			name:     "non-video type - SPS (33)",
			naluType: NALU_SPS,
			want:     false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := IsVideoNaluType(tc.naluType)
			if got != tc.want {
				t.Errorf("IsVideoNaluType(%d) = %v; want %v", tc.naluType, got, tc.want)
			}
		})
	}
}
