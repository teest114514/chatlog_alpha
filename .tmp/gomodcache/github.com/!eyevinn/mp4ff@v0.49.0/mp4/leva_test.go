package mp4_test

import (
	"testing"

	"github.com/Eyevinn/mp4ff/mp4"
)

func TestLeva(t *testing.T) {
	leva := mp4.LevaBox{}
	lvl, err := mp4.NewLevaLevel(1, true, 0, 42, 0, 0)
	if err != nil {
		t.Error(err)
	}
	leva.Levels = append(leva.Levels, lvl)
	lvl, err = mp4.NewLevaLevel(2, false, 1, 42, 43, 0)
	if err != nil {
		t.Error(err)
	}
	leva.Levels = append(leva.Levels, lvl)
	lvl, err = mp4.NewLevaLevel(2, false, 2, 0, 0, 0)
	if err != nil {
		t.Error(err)
	}
	leva.Levels = append(leva.Levels, lvl)
	lvl, err = mp4.NewLevaLevel(2, false, 3, 0, 0, 0)
	if err != nil {
		t.Error(err)
	}
	leva.Levels = append(leva.Levels, lvl)
	lvl, err = mp4.NewLevaLevel(3, false, 4, 0, 0, 44)
	if err != nil {
		t.Error(err)
	}
	leva.Levels = append(leva.Levels, lvl)
	boxDiffAfterEncodeAndDecode(t, &leva)
}
