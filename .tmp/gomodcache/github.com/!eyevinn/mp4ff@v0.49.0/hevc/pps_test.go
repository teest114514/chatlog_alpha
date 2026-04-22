package hevc

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/go-test/deep"
)

func TestPPSParser(t *testing.T) {
	testCases := []struct {
		hexData string
		spsID   uint32
		wanted  PPS
	}{
		{
			"4401c0f7c0cc90",
			0,
			PPS{
				CabacInitPresentFlag:               true,
				TransformSkipEnabledFlag:           true,
				CuQpDeltaEnabledFlag:               true,
				LoopFilterAcrossSlicesEnabledFlag:  true,
				DeblockingFilterControlPresentFlag: true,
			},
		},
		{
			"4401c172b46240",
			0,
			PPS{
				SignDataHidingEnabledFlag:         true,
				CuQpDeltaEnabledFlag:              true,
				DiffCuQpDeltaDepth:                1,
				WeightedPredFlag:                  true,
				LoopFilterAcrossSlicesEnabledFlag: true,
				EntropyCodingSyncEnabledFlag:      true,
			},
		},
		{
			"4401c1ac9383b240",
			0,
			PPS{
				CabacInitPresentFlag:                true,
				NumRefIdxL0DefaultActiveMinus1:      1,
				SignDataHidingEnabledFlag:           true,
				CuQpDeltaEnabledFlag:                true,
				DiffCuQpDeltaDepth:                  3,
				DeblockingFilterControlPresentFlag:  true,
				DeblockingFilterOverrideEnabledFlag: true,
				LoopFilterAcrossSlicesEnabledFlag:   true,
				SliceChromaQpOffsetsPresentFlag:     true,
			},
		},
	}

	for i, tc := range testCases {
		t.Run(fmt.Sprintf("case %d_%s", i, tc.hexData), func(t *testing.T) {

			byteData, err := hex.DecodeString(tc.hexData)
			if err != nil {
				t.Error(err)
			}
			spsMap := map[uint32]*SPS{
				tc.spsID: nil,
			}
			got, err := ParsePPSNALUnit(byteData, spsMap)
			if err != nil {
				t.Error(err)
				return
			}
			if diff := deep.Equal(&tc.wanted, got); diff != nil {
				t.Error(diff)
			}
		})
	}
}
