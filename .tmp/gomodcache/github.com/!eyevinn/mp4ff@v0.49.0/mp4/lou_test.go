package mp4_test

import (
	"testing"

	"github.com/Eyevinn/mp4ff/mp4"
)

func TestTlou(t *testing.T) {
	tlou := mp4.LoudnessBaseBox{
		Name:    "tlou",
		Version: 1,
		Flags:   0,
		LoudnessBases: []*mp4.LoudnessBase{
			{
				EQSetID:                0,
				DownmixID:              0,
				DRCSetID:               0,
				BsSamplePeakLevel:      1087,
				BsTruePeakLevel:        1086,
				MeasurementSystemForTP: 2,
				ReliabilityForTP:       3,
				Measurements: []mp4.LoudnessMeasurement{
					{
						MethodDefinition:  1,
						MethodValue:       121,
						MeasurementSystem: 2,
						Reliability:       3,
					},
					{
						MethodDefinition:  3,
						MethodValue:       122,
						MeasurementSystem: 1,
						Reliability:       3,
					},
				},
			},
			{
				EQSetID:                0,
				DownmixID:              0,
				DRCSetID:               0,
				BsSamplePeakLevel:      1087,
				BsTruePeakLevel:        1086,
				MeasurementSystemForTP: 2,
				ReliabilityForTP:       3,
				Measurements: []mp4.LoudnessMeasurement{
					{
						MethodDefinition:  4,
						MethodValue:       124,
						MeasurementSystem: 1,
						Reliability:       3,
					},
					{
						MethodDefinition:  5,
						MethodValue:       122,
						MeasurementSystem: 1,
						Reliability:       3,
					},
				},
			},
		},
	}
	boxDiffAfterEncodeAndDecode(t, &tlou)
}
