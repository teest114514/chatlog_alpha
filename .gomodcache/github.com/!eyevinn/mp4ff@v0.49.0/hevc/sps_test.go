package hevc

import (
	"encoding/hex"
	"testing"

	"github.com/go-test/deep"
)

const (
	spsNalu = ("420101022000000300b0000003000003007ba0078200887db6718b92448053888892" +
		"cf24a69272c9124922dc91aa48fca223ff000100016a02020201")
	spsNaluHdr10 = "420101022000000300b0000003000003009ca001e020021c4d8815ee4595602d4244024020"
	spsNaluHrd   = ("42010101400000030000030000030000030096a001e02002207c4e5ad290964b8c04040000" +
		"03000400000300658017794400014fb1000004c4b3c40")
)

func TestSPSParser1(t *testing.T) {
	byteData, _ := hex.DecodeString(spsNalu)

	wantedVUI := VUIParameters{
		SampleAspectRatioWidth:     1,
		SampleAspectRatioHeight:    1,
		VideoSignalTypePresentFlag: true,
		VideoFormat:                5,
		ColourDescriptionFlag:      true,
		ColourPrimaries:            1,
		TransferCharacteristics:    1,
		MatrixCoefficients:         1,
	}
	wanted := SPS{
		VpsID:                 0,
		MaxSubLayersMinus1:    0,
		TemporalIDNestingFlag: true,
		ProfileTierLevel: ProfileTierLevel{
			GeneralProfileSpace:              0,
			GeneralTierFlag:                  false,
			GeneralProfileIDC:                2,
			GeneralProfileCompatibilityFlags: 536870912,
			GeneralConstraintIndicatorFlags:  193514046488576,
			GeneralProgressiveSourceFlag:     true,
			GeneralInterlacedSourceFlag:      false,
			GeneralNonPackedConstraintFlag:   true,
			GeneralFrameOnlyConstraintFlag:   true,
			GeneralLevelIDC:                  123,
		},
		SpsID:                   0,
		ChromaFormatIDC:         1,
		SeparateColourPlaneFlag: false,
		ConformanceWindowFlag:   true,
		PicWidthInLumaSamples:   960,
		PicHeightInLumaSamples:  544,
		ConformanceWindow: ConformanceWindow{
			LeftOffset:   0,
			RightOffset:  0,
			TopOffset:    0,
			BottomOffset: 2,
		},
		BitDepthLumaMinus8:              2,
		BitDepthChromaMinus8:            2,
		Log2MaxPicOrderCntLsbMinus4:     6,
		SubLayerOrderingInfoPresentFlag: false,
		SubLayeringOrderingInfos: []SubLayerOrderingInfo{
			{
				MaxDecPicBufferingMinus1: 5,
				MaxNumReorderPics:        4,
				MaxLatencyIncreasePlus1:  0,
			},
		},
		Log2MinLumaCodingBlockSizeMinus3:     0,
		Log2DiffMaxMinLumaCodingBlockSize:    3,
		Log2MinLumaTransformBlockSizeMinus2:  0,
		Log2DiffMaxMinLumaTransformBlockSize: 3,
		MaxTransformHierarchyDepthInter:      1,
		MaxTransformHierarchyDepthIntra:      1,
		ScalingListEnabledFlag:               false,
		ScalingListDataPresentFlag:           false,
		AmpEnabledFlag:                       false,
		SampleAdaptiveOffsetEnabledFlag:      false,
		PCMEnabledFlag:                       false,
		NumShortTermRefPicSets:               9,
		ShortTermRefPicSets: []ShortTermRPS{
			{
				DeltaPocS0:      []uint32{8, 8},
				DeltaPocS1:      []uint32{},
				UsedByCurrPicS0: []bool{true, true},
				UsedByCurrPicS1: []bool{},
				NumNegativePics: 2,
				NumPositivePics: 0,
				NumDeltaPocs:    2,
			},
			{
				DeltaPocS0:      []uint32{1},
				DeltaPocS1:      []uint32{7},
				UsedByCurrPicS0: []bool{true},
				UsedByCurrPicS1: []bool{true},
				NumNegativePics: 1,
				NumPositivePics: 1,
				NumDeltaPocs:    2,
			},
			{
				DeltaPocS0:      []uint32{2},
				DeltaPocS1:      []uint32{6},
				UsedByCurrPicS0: []bool{true},
				UsedByCurrPicS1: []bool{true},
				NumNegativePics: 1,
				NumPositivePics: 1,
				NumDeltaPocs:    2,
			},
			{
				DeltaPocS0:      []uint32{3},
				DeltaPocS1:      []uint32{5},
				UsedByCurrPicS0: []bool{true},
				UsedByCurrPicS1: []bool{true},
				NumNegativePics: 1,
				NumPositivePics: 1,
				NumDeltaPocs:    2,
			},
			{
				DeltaPocS0:      []uint32{4},
				DeltaPocS1:      []uint32{4},
				UsedByCurrPicS0: []bool{true},
				UsedByCurrPicS1: []bool{true},
				NumNegativePics: 1,
				NumPositivePics: 1,
				NumDeltaPocs:    2,
			},
			{
				DeltaPocS0:      []uint32{5},
				DeltaPocS1:      []uint32{3},
				UsedByCurrPicS0: []bool{true},
				UsedByCurrPicS1: []bool{true},
				NumNegativePics: 1,
				NumPositivePics: 1,
				NumDeltaPocs:    2,
			},
			{
				DeltaPocS0:      []uint32{6},
				DeltaPocS1:      []uint32{2},
				UsedByCurrPicS0: []bool{true},
				UsedByCurrPicS1: []bool{true},
				NumNegativePics: 1,
				NumPositivePics: 1,
				NumDeltaPocs:    2,
			},
			{
				DeltaPocS0:      []uint32{7},
				DeltaPocS1:      []uint32{1},
				UsedByCurrPicS0: []bool{true},
				UsedByCurrPicS1: []bool{true},
				NumNegativePics: 1,
				NumPositivePics: 1,
				NumDeltaPocs:    2,
			},
			{
				DeltaPocS0:      []uint32{8},
				DeltaPocS1:      []uint32{},
				UsedByCurrPicS0: []bool{true},
				UsedByCurrPicS1: []bool{},
				NumNegativePics: 1,
				NumPositivePics: 0,
				NumDeltaPocs:    1,
			},
		},
		LongTermRefPicsPresentFlag:      false,
		SpsTemporalMvpEnabledFlag:       false,
		StrongIntraSmoothingEnabledFlag: false,
		VUIParametersPresentFlag:        true,
		VUI:                             &wantedVUI,
	}
	got, err := ParseSPSNALUnit(byteData)
	if err != nil {
		t.Fatal("Error parsing SPS")
	}

	if diff := deep.Equal(*got, wanted); diff != nil {
		t.Error(diff)
	}
	gotWidth, gotHeight := got.ImageSize()
	var expWidth, expHeight uint32 = 960, 540
	if gotWidth != expWidth || gotHeight != expHeight {
		t.Errorf("Got %dx%d instead of %dx%d", gotWidth, gotHeight, expWidth, expHeight)
	}
}

func TestSPSParser2(t *testing.T) {
	byteData, _ := hex.DecodeString(spsNaluHdr10)

	wantedVUI := VUIParameters{
		SampleAspectRatioWidth:     1,
		SampleAspectRatioHeight:    1,
		VideoSignalTypePresentFlag: true,
		VideoFormat:                5,
		ColourDescriptionFlag:      true,
		ColourPrimaries:            9,
		TransferCharacteristics:    16,
		MatrixCoefficients:         9,
	}
	wanted := SPS{
		VpsID:                 0,
		MaxSubLayersMinus1:    0,
		TemporalIDNestingFlag: true,
		ProfileTierLevel: ProfileTierLevel{
			GeneralProfileSpace:              0,
			GeneralTierFlag:                  false,
			GeneralProfileIDC:                2,
			GeneralProfileCompatibilityFlags: 536870912,
			GeneralConstraintIndicatorFlags:  193514046488576,
			GeneralProgressiveSourceFlag:     true,
			GeneralInterlacedSourceFlag:      false,
			GeneralNonPackedConstraintFlag:   true,
			GeneralFrameOnlyConstraintFlag:   true,
			GeneralLevelIDC:                  156,
		},
		SpsID:                   0,
		ChromaFormatIDC:         1,
		SeparateColourPlaneFlag: false,
		ConformanceWindowFlag:   false,
		PicWidthInLumaSamples:   3840,
		PicHeightInLumaSamples:  2160,
		ConformanceWindow: ConformanceWindow{
			LeftOffset:   0,
			RightOffset:  0,
			TopOffset:    0,
			BottomOffset: 0,
		},
		BitDepthLumaMinus8:              2,
		BitDepthChromaMinus8:            2,
		Log2MaxPicOrderCntLsbMinus4:     7,
		SubLayerOrderingInfoPresentFlag: false,
		SubLayeringOrderingInfos: []SubLayerOrderingInfo{
			{
				MaxDecPicBufferingMinus1: 4,
				MaxNumReorderPics:        2,
				MaxLatencyIncreasePlus1:  0,
			},
		},
		Log2MinLumaCodingBlockSizeMinus3:     0,
		Log2DiffMaxMinLumaCodingBlockSize:    2,
		Log2MinLumaTransformBlockSizeMinus2:  0,
		Log2DiffMaxMinLumaTransformBlockSize: 3,
		MaxTransformHierarchyDepthInter:      1,
		MaxTransformHierarchyDepthIntra:      0,
		ScalingListEnabledFlag:               true,
		ScalingListDataPresentFlag:           false,
		AmpEnabledFlag:                       false,
		SampleAdaptiveOffsetEnabledFlag:      true,
		PCMEnabledFlag:                       false,
		NumShortTermRefPicSets:               0,
		LongTermRefPicsPresentFlag:           false,
		SpsTemporalMvpEnabledFlag:            true,
		StrongIntraSmoothingEnabledFlag:      false,
		VUIParametersPresentFlag:             true,
		VUI:                                  &wantedVUI,
	}
	got, err := ParseSPSNALUnit(byteData)
	if err != nil {
		t.Error("Error parsing SPS")
	}

	if diff := deep.Equal(*got, wanted); diff != nil {
		t.Error(diff)
	}
	gotWidth, gotHeight := got.ImageSize()
	var expWidth, expHeight uint32 = 3840, 2160
	if gotWidth != expWidth || gotHeight != expHeight {
		t.Errorf("Got %dx%d instead of %dx%d", gotWidth, gotHeight, expWidth, expHeight)
	}
}

func TestSPSParser3(t *testing.T) {
	byteData, _ := hex.DecodeString(spsNaluHrd)

	wantedHrd := HrdParameters{
		NalHrdParametersPresentFlag:        true,
		InitialCpbRemovalDelayLengthMinus1: 23,
		AuCpbRemovalDelayLengthMinus1:      15,
		DpbOutputDelayLengthMinus1:         5,
		SubLayerHrd: []SubLayerHrd{
			{
				NalHrdParameters: []SubLayerHrdParameters{
					{
						BitRateValueMinus1: 171873,
						CpbSizeValueMinus1: 1249998,
					},
				},
			},
		},
	}

	wantedVUI := VUIParameters{
		SampleAspectRatioWidth:     1,
		SampleAspectRatioHeight:    1,
		VideoSignalTypePresentFlag: false,
		VideoFormat:                0,
		ColourDescriptionFlag:      false,
		ColourPrimaries:            0,
		TransferCharacteristics:    0,
		MatrixCoefficients:         0,
		TimingInfoPresentFlag:      true,
		NumUnitsInTick:             1,
		TimeScale:                  25,
		HrdParametersPresentFlag:   true,
		HrdParameters:              &wantedHrd,
	}
	wanted := SPS{
		VpsID:                 0,
		MaxSubLayersMinus1:    0,
		TemporalIDNestingFlag: true,
		ProfileTierLevel: ProfileTierLevel{
			GeneralProfileSpace:              0,
			GeneralProfileIDC:                1,
			GeneralProfileCompatibilityFlags: 1073741824,
			GeneralLevelIDC:                  150,
		},
		SpsID:                   0,
		ChromaFormatIDC:         1,
		SeparateColourPlaneFlag: false,
		ConformanceWindowFlag:   true,
		PicWidthInLumaSamples:   3840,
		PicHeightInLumaSamples:  2176,
		ConformanceWindow: ConformanceWindow{
			LeftOffset:   0,
			RightOffset:  0,
			TopOffset:    0,
			BottomOffset: 8,
		},
		Log2MaxPicOrderCntLsbMinus4:     4,
		SubLayerOrderingInfoPresentFlag: true,
		SubLayeringOrderingInfos: []SubLayerOrderingInfo{
			{
				MaxDecPicBufferingMinus1: 1,
				MaxNumReorderPics:        0,
				MaxLatencyIncreasePlus1:  0,
			},
		},
		Log2MinLumaCodingBlockSizeMinus3:     1,
		Log2DiffMaxMinLumaCodingBlockSize:    1,
		Log2MinLumaTransformBlockSizeMinus2:  0,
		Log2DiffMaxMinLumaTransformBlockSize: 3,
		MaxTransformHierarchyDepthInter:      3,
		MaxTransformHierarchyDepthIntra:      0,
		ScalingListEnabledFlag:               false,
		ScalingListDataPresentFlag:           false,
		AmpEnabledFlag:                       true,
		SampleAdaptiveOffsetEnabledFlag:      true,
		PCMEnabledFlag:                       false,
		NumShortTermRefPicSets:               1,
		ShortTermRefPicSets: []ShortTermRPS{
			{
				DeltaPocS0:      []uint32{1},
				DeltaPocS1:      []uint32{},
				UsedByCurrPicS0: []bool{true},
				UsedByCurrPicS1: []bool{},
				NumNegativePics: 1,
				NumPositivePics: 0,
				NumDeltaPocs:    1,
			},
		},
		LongTermRefPicsPresentFlag:      false,
		SpsTemporalMvpEnabledFlag:       false,
		StrongIntraSmoothingEnabledFlag: false,
		VUIParametersPresentFlag:        true,
		VUI:                             &wantedVUI,
	}
	got, err := ParseSPSNALUnit(byteData)
	if err != nil {
		t.Error("Error parsing SPS")
	}

	if diff := deep.Equal(*got, wanted); diff != nil {
		t.Error(diff)
	}
	gotWidth, gotHeight := got.ImageSize()
	var expWidth, expHeight uint32 = 3840, 2160
	if gotWidth != expWidth || gotHeight != expHeight {
		t.Errorf("Got %dx%d instead of %dx%d", gotWidth, gotHeight, expWidth, expHeight)
	}
}

// TestParseSPSWithNonZeroNumDeltaPocs checks that parsing succeeds (Github issue #279)
func TestParseSPSWithNonZeroNumDeltaPocs(t *testing.T) {
	data := []byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255,
		3, 32, 0, 1, 0, 25, 64, 1, 12, 1, 255, 255, 1, 96, 0, 0, 3, 0, 0, 3, 0, 0, 3,
		0, 0, 3, 0, 153, 53, 2, 64, 33, 0, 1, 0, 40, 66, 1, 1, 1, 96, 0, 0, 3, 0, 0, 3,
		0, 0, 3, 0, 0, 3, 0, 153, 160, 2, 128, 128, 45, 22, 141, 82, 187, 34, 186, 173,
		146, 169, 119, 53, 1, 1, 1, 0, 128, 34, 0, 1, 0, 8, 68, 1, 192, 36, 103, 192, 204, 100}
	hevcd, err := DecodeHEVCDecConfRec(data)
	if err != nil {
		t.Error(err)
	}

	spsBytes := hevcd.GetNalusForType(NALU_SPS)
	if len(spsBytes) != 1 {
		t.Error("expected 1 sps NALU")
	}
	sps, err := ParseSPSNALUnit(spsBytes[0])
	if err != nil {
		t.Error(err)
	}
	t.Log(sps)
}

// Use SPS and PPS from https://www.itu.int/wftp3/av-arch/jctvc-site/bitstream_exchange/under_test/
// to get bigger variety of input. Don't consider the actual output, just check that parsing works
func TestSPSandPPS(t *testing.T) {
	cases := []struct {
		desc string
		vps  string
		sps  string
		pps  string
	}{
		{
			desc: "Zero_and_One_Palette_Size_A_Canon_2",
			vps:  "40010c01ffff090040000003000c000003000078ac09",
			sps:  "420101090040000003000c00000300007890007810021cff2d7248db3db643cd81000843",
			pps:  "4401c194964c08b21bdd",
		},
		{
			desc: "SPSSLIST_A_Sony_1",
			vps: "40010c11ffff0701000003000f8800000300007bb5057000003e90000ea6077b1000043024e0f00000030001f10000030" +
				"0000f75880f000882807b050002d0a00e36bdff90a020202c1",
			sps: "4201010160000003000003000003000003007ba0078200887de5b59246f8f2c997932c8501e003fe03fa80203c07f2804" +
				"06010163c040018407001840c203040c206103080c10308184070018404042607f03000e1030018006001800c00600180" +
				"06003000e1030008194d10730a3cc3849cc2028709c2464e1309528240a42a09620114201182304828928b1c9362398c7" +
				"1d14c21ff5ebe4fc47f5f9be2bc21c35822828358f840787878f0583c78f0743c78f1e0481e3c78f1e0561e3c78f1e3c0" +
				"c83c78f1e3c78f0320f1e3c78f1e0561e3c78f1e0481e3c78f0743c78f0583c78787842340fc101e1e1e3c160f1e3c1d0" +
				"f1e3c7812078f1e3c7815878f1e3c78f0320f1e3c78f1e3c0c83c78f1e3c7815878f1e3c7812078f1e3c1d0f1e3c160f1" +
				"e1e1e1063c041840787878f0583c78f0743c78f1e0481e3c78f1e0561e3c78f1e3c0c83c78f1e3c78f0320f1e3c78f1e0" +
				"561e3c78f1e0481e3c78f0743c78f0583c7878784203b80202111c1f1c38168e1c381d8e1c387012470e1c387015c70e1" +
				"c3870e0328e1c3870e1c380ca3870e1c387015c70e1c387012470e1c381d8e1c38168e1c1f1c11807b8040844707c70e0" +
				"5a3870e0763870e1c0491c3870e1c0571c3870e1c380ca3870e1c3870e0328e1c3870e1c0571c3870e1c0491c3870e076" +
				"3870e05a38707c70463c07e044707c70e05a3870e0763870e1c0491c3870e1c0571c3870e1c380ca3870e1c3870e0328e" +
				"1c3870e1c0571c3870e1c0491c3870e0763870e05a38707c7045c45525ed9",
			pps: "4401c1f5811d02a0",
		},
	}
	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			//vpsBytes, _ := hex.DecodeString(c.vps)
			spsBytes, _ := hex.DecodeString(c.sps)
			ppsBytes, _ := hex.DecodeString(c.pps)

			sps, err := ParseSPSNALUnit(spsBytes)
			if err != nil {
				t.Error("Error parsing SPS Nal unit")
			}
			spsMap := make(map[uint32]*SPS)
			spsMap[uint32(sps.SpsID)] = sps
			pps, err := ParsePPSNALUnit(ppsBytes, spsMap)
			if err != nil {
				t.Error("Error parsing PPS Nal unit")
			}
			if byte(pps.SeqParameterSetID) != sps.SpsID {
				t.Error("PPS SpsID does not match SPS SpsID")
			}
		})
	}

}
