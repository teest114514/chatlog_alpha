package hevc

import (
	"encoding/hex"
	"testing"

	"github.com/Eyevinn/mp4ff/sei"
)

func TestSEIParsing(t *testing.T) {
	testCases := []struct {
		desc               string
		spsNALUHex         string
		seiNALUHex         string
		expectedMsgs       []sei.SEIMessage
		expectedFrameField *sei.HEVCFrameFieldInfo
		expectedErr        error
	}{
		{
			desc:         "Test SEI HEVC pic_timing with SPS",
			spsNALUHex:   "420101014000000300400000030000030078a003c080221f7a3ee46c1bdf4f60280d00000303e80000c350601def7e00028b1c001443c8",
			seiNALUHex:   "4e0101071000001a0000030180",
			expectedMsgs: []sei.SEIMessage{&sei.PicTimingHevcSEI{}},
			expectedFrameField: &sei.HEVCFrameFieldInfo{
				PicStruct:      1,
				SourceScanType: 0,
				DuplicateFlag:  false,
			},
			expectedErr: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			spsBytes, err := hex.DecodeString(tc.spsNALUHex)
			if err != nil {
				t.Error(err)
			}
			sps, err := ParseSPSNALUnit(spsBytes)
			if err != nil {
				t.Fatalf("ParseSPSNALU failed: %v", err)
			}
			seiBytes, err := hex.DecodeString(tc.seiNALUHex)
			if err != nil {
				t.Error(err)
			}
			msgs, err := ParseSEINalu(seiBytes, sps)
			if err != tc.expectedErr {
				t.Fatalf("expected err %q got : %v", tc.expectedErr, err)
			}
			if len(msgs) != len(tc.expectedMsgs) {
				t.Fatalf("Expected %d messages, got %d", len(tc.expectedMsgs), len(msgs))
			}
			for i, msg := range msgs {
				msgType := msg.Type()
				if msgType != tc.expectedMsgs[i].Type() {
					t.Errorf("Expected message type %d, got %d", tc.expectedMsgs[i].Type(), msg.Type())
				}
				if (msg.Type() == sei.SEIPicTimingType) && tc.expectedFrameField != nil {
					picTimeSEI := msg.(*sei.PicTimingHevcSEI)
					gotFrameField := picTimeSEI.FrameFieldInfo
					if *gotFrameField != *tc.expectedFrameField {
						t.Errorf("Expected framefield %+v, got %+v", tc.expectedFrameField, gotFrameField)
					}
				}
			}
		})
	}
}
