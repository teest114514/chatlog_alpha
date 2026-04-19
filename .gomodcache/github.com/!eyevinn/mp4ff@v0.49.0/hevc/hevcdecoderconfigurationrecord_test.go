package hevc

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func TestCreateDecConfRec(t *testing.T) {
	testCases := []struct {
		vpsHex    string
		spsHex    string
		ppsHex    string
		seiHex    string
		complete  bool
		includePS bool
		errorMsg  string
	}{
		{
			vpsHex:    "",
			spsHex:    "",
			ppsHex:    "",
			seiHex:    "",
			complete:  false,
			includePS: false,
			errorMsg:  "no SPS NALU supported. Needed to extract fundamental information",
		},
		{
			vpsHex:    "0000000140010c01ffff016000000300900000030000030078959809",
			spsHex:    "00000001420101016000000300900000030000030078a00502016965959a4932bc05a80808082000000300200000030321",
			ppsHex:    "000000014401c172b46240",
			seiHex:    "000000014e01891800000300000300000300000300000300000300000300000300000300000300000300009004000003000080",
			complete:  true,
			includePS: true,
			errorMsg:  "",
		},
	}
	for _, tc := range testCases {
		vpsNalus := createNalusFromHex(tc.vpsHex)
		spsNalus := createNalusFromHex(tc.spsHex)
		ppsNalus := createNalusFromHex(tc.ppsHex)
		seiNalus := createNalusFromHex(tc.seiHex)
		dcr, err := CreateHEVCDecConfRec(vpsNalus, spsNalus, ppsNalus,
			tc.complete, tc.complete, tc.complete, tc.includePS)
		seiArray := NewNaluArray(tc.complete, NALU_SEI_PREFIX, seiNalus)
		dcr.AddNaluArrays([]NaluArray{seiArray})
		if tc.errorMsg != "" {
			if err.Error() != tc.errorMsg {
				t.Errorf("got error %q instead of %q", err.Error(), tc.errorMsg)
			}
		} else {
			if len(dcr.NaluArrays) != 4 {
				t.Errorf("got %d NALU arrays instead of 4", len(dcr.NaluArrays))
			}
			for i, naluArray := range dcr.NaluArrays {
				if naluArray.Complete() != 0 {
					if len(naluArray.Nalus) == 0 {
						t.Errorf("missing NALUs in naluArray %d", i)
					}
				}
			}
		}
	}
}

func createNalusFromHex(hexStr string) [][]byte {
	if hexStr == "" {
		return nil
	}
	startCode := "00000001"
	parts := strings.Split(hexStr, startCode)
	nalusHex := parts[1:]
	nalus := make([][]byte, 0, len(nalusHex))
	for _, nx := range nalusHex {
		nalu, _ := hex.DecodeString(nx)
		nalus = append(nalus, nalu)
	}
	return nalus
}

func TestDecodeConfRec(t *testing.T) {
	hexData := ("0102" +
		"00000020b000000000009c0000000102" +
		"0200000f03a00001001840010c01ffff" +
		"022000000300b0000003000003009c15" +
		"c090a100010025420101022000000300" +
		"b0000003000003009ca001e020021c4d" +
		"8815ee4595602d4244024020a2000100" +
		"094401c02864b8d05324")
	data, err := hex.DecodeString(hexData)
	if err != nil {
		t.Error(err)
	}
	hdcr, err := DecodeHEVCDecConfRec(data)
	if err != nil {
		t.Error(err)
	}
	for _, na := range hdcr.NaluArrays {
		switch na.NaluType() {
		case NALU_VPS, NALU_PPS:
		case NALU_SPS:
			for _, nalu := range na.Nalus {
				sps, err := ParseSPSNALUnit(nalu)
				if err != nil {
					t.Error(err)
				}
				if !sps.ScalingListEnabledFlag || sps.ScalingListDataPresentFlag {
					t.Error("scaling_list_enabled not properly parsed")
				}
				vui := sps.VUI
				if vui == nil {
					t.Error("no vui parsed")
				} else {
					if vui.TransferCharacteristics != 16 {
						t.Errorf("vui transfer_characteristics is %d, not 16", vui.TransferCharacteristics)
					}
					if vui.ColourPrimaries != 9 {
						t.Errorf("vui colour_primaries is %d, not 9", vui.ColourPrimaries)
					}
					if vui.MatrixCoefficients != 9 {
						t.Errorf("vui matrix_coefficients is %d, not 9", vui.MatrixCoefficients)
					}
				}
			}
		default:
			t.Errorf("strange nalu type %s", na.NaluType())
		}
	}

	out := bytes.Buffer{}
	err = hdcr.Encode(&out)
	if err != nil {
		t.Error(err)
	}
}
