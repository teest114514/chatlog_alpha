package hevc

import (
	"os"
	"testing"

	"github.com/Eyevinn/mp4ff/avc"

	"github.com/go-test/deep"
)

func TestParseSliceHeader(t *testing.T) {
	wantedHdr := map[NaluType]SliceHeader{
		NALU_IDR_N_LP: {
			SliceType:                         SLICE_I,
			FirstSliceSegmentInPicFlag:        true,
			SaoLumaFlag:                       true,
			SaoChromaFlag:                     true,
			QpDelta:                           7,
			LoopFilterAcrossSlicesEnabledFlag: true,
			NumEntryPointOffsets:              1,
			OffsetLenMinus1:                   3,
			CollocatedFromL0Flag:              true,
			EntryPointOffsetMinus1:            []uint32{12},
			Size:                              6},
		NALU_TRAIL_N: {
			SliceType:                  SLICE_B,
			FirstSliceSegmentInPicFlag: true,
			PicOrderCntLsb:             1,
			ShortTermRefPicSet: ShortTermRPS{
				DeltaPocS0:      []uint32{1},
				DeltaPocS1:      []uint32{2, 2},
				UsedByCurrPicS0: []bool{true},
				UsedByCurrPicS1: []bool{true, true},
				NumNegativePics: 1,
				NumPositivePics: 2,
				NumDeltaPocs:    3,
			},
			SaoLumaFlag:                       true,
			SaoChromaFlag:                     true,
			TemporalMvpEnabledFlag:            true,
			NumRefIdxActiveOverrideFlag:       true,
			NumRefIdxL0ActiveMinus1:           0,
			NumRefIdxL1ActiveMinus1:           1,
			FiveMinusMaxNumMergeCand:          2,
			QpDelta:                           10,
			LoopFilterAcrossSlicesEnabledFlag: true,
			NumEntryPointOffsets:              1,
			OffsetLenMinus1:                   1,
			CollocatedFromL0Flag:              false,
			EntryPointOffsetMinus1:            []uint32{1},
			Size:                              10,
		},
		NALU_TRAIL_R: {
			SliceType:                  SLICE_P,
			FirstSliceSegmentInPicFlag: true,
			PicOrderCntLsb:             5,
			ShortTermRefPicSet: ShortTermRPS{
				DeltaPocS0:      []uint32{5},
				DeltaPocS1:      []uint32{},
				UsedByCurrPicS0: []bool{true},
				UsedByCurrPicS1: []bool{},
				NumNegativePics: 1,
				NumDeltaPocs:    1,
			},
			SaoLumaFlag:            true,
			SaoChromaFlag:          true,
			TemporalMvpEnabledFlag: true,
			PredWeightTable: &PredWeightTable{
				LumaLog2WeightDenom:        7,
				DeltaChromaLog2WeightDenom: -1,
				WeightsL0: []WeightingFactors{
					{
						LumaWeightFlag:   false,
						ChromaWeightFlag: false,
					},
				},
			},
			CollocatedFromL0Flag:     true,
			FiveMinusMaxNumMergeCand: 2,
			QpDelta:                  7,
			NumEntryPointOffsets:     1,
			OffsetLenMinus1:          1,
			EntryPointOffsetMinus1:   []uint32{2},
			Size:                     10,
		},
	}
	data, err := os.ReadFile("testdata/blackframe.265")
	if err != nil {
		t.Error(err)
	}
	nalus := avc.ExtractNalusFromByteStream(data)
	spsMap := make(map[uint32]*SPS, 1)
	ppsMap := make(map[uint32]*PPS, 1)
	gotHdr := make(map[NaluType]SliceHeader)
	for _, nalu := range nalus {
		switch GetNaluType(nalu[0]) {
		case NALU_SPS:
			sps, err := ParseSPSNALUnit(nalu)
			if err != nil {
				t.Error(err)
			}
			spsMap[uint32(sps.SpsID)] = sps
		case NALU_PPS:
			pps, err := ParsePPSNALUnit(nalu, spsMap)
			if err != nil {
				t.Error(err)
			}
			ppsMap[pps.PicParameterSetID] = pps
		case NALU_IDR_N_LP, NALU_TRAIL_R, NALU_TRAIL_N:
			hdr, err := ParseSliceHeader(nalu, spsMap, ppsMap)
			if err != nil {
				t.Error(err)
			}
			gotHdr[GetNaluType(nalu[0])] = *hdr
		}
	}
	if diff := deep.Equal(wantedHdr, gotHdr); diff != nil {
		t.Errorf("Got Slice Headers: %+v\n Diff is %v", gotHdr, diff)
	}
}
