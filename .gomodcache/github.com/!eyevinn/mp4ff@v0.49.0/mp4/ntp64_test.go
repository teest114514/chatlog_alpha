package mp4_test

import (
	"testing"
	"time"

	"github.com/Eyevinn/mp4ff/mp4"
)

func TestNTP64(t *testing.T) {
	cases := []struct {
		desc         string
		ntp          mp4.NTP64
		expectedUTC  float64
		expectedTime time.Time
	}{
		{"1970-01-01", mp4.NTP64(mp4.NTPEpochOffset << 32), 0, time.Unix(0, 0).UTC()},
		{"+1s", mp4.NTP64((mp4.NTPEpochOffset + 1) << 32), 1.0, time.Unix(1, 0).UTC()},
		{"+0.5s", mp4.NTP64((mp4.NTPEpochOffset << 32) + (1 << 31)), 0.5, time.Unix(0, 500_000_000).UTC()},
		{"1.25s", mp4.NewNTP64(1.25), 1.25, time.Unix(1, 250_000_000).UTC()},
		{"2024-date", mp4.NewNTP64(1725828561.125), 1725828561.125, time.Unix(1725828561, 125_000_000).UTC()},
	}

	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			if c.ntp.UTC() != c.expectedUTC {
				t.Errorf("Expected %f, got %f", c.expectedUTC, c.ntp.UTC())
			}
			if c.ntp.Time() != c.expectedTime {
				t.Errorf("Expected %s, got %s", c.expectedTime, c.ntp.Time())
			}
		})
	}
}

func TestNTP64String(t *testing.T) {
	ntp := mp4.NewNTP64(1725612561.375)
	expected := "2024-09-06 08:49:21.375 +0000 UTC"
	if ntp.String() != expected {
		t.Errorf("Expected %s, got %s", expected, ntp.String())
	}
}
