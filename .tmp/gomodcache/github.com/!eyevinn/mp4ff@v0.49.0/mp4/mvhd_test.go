package mp4_test

import (
	"bytes"
	"os"
	"testing"

	"github.com/Eyevinn/mp4ff/mp4"
)

func TestMvhd(t *testing.T) {
	mvhd := mp4.CreateMvhd()
	boxDiffAfterEncodeAndDecode(t, mvhd)

	recentTime := int64(1721459921)
	mvhd.SetCreationTimeS(recentTime)
	mvhd.SetModificationTimeS(recentTime)
	if mvhd.CreationTimeS() != recentTime {
		t.Errorf("CreationTimeS %d not %d", mvhd.CreationTimeS(), recentTime)
	}
	if mvhd.ModificationTimeS() != recentTime {
		t.Errorf("ModificationTimeS %d not %d", mvhd.ModificationTimeS(), recentTime)
	}
}

func TestMvhdTimeDecodeS(t *testing.T) {
	data, err := os.ReadFile("testdata/mvhd_1970.dat")
	if err != nil {
		t.Error(err)
	}
	reader := bytes.NewReader(data)
	box, err := mp4.DecodeBox(0, reader)
	if err != nil {
		t.Error(err)
	}
	mvhd, ok := box.(*mp4.MvhdBox)
	if !ok {
		t.Errorf("Not a MvhdBox %+v", box)
	}
	if mvhd.CreationTimeS() != 0 {
		t.Errorf("CreationTimeS %d not 0", mvhd.CreationTimeS())
	}
	if mvhd.ModificationTimeS() != 0 {
		t.Errorf("ModificationTimeS %d not 0", mvhd.ModificationTimeS())
	}
}
