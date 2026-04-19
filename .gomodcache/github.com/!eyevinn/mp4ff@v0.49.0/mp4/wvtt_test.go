package mp4_test

import (
	"testing"

	"github.com/Eyevinn/mp4ff/mp4"
)

func TestVttc(t *testing.T) {

	vttc := &mp4.VttcBox{}
	vttc.AddChild(&mp4.VsidBox{SourceID: 42})
	vttc.AddChild(&mp4.CtimBox{CueCurrentTime: "00:00:00.120"})
	vttc.AddChild(&mp4.IdenBox{CueID: "ten"})
	vttc.AddChild(&mp4.SttgBox{Settings: "line:20%"})
	vttc.AddChild(&mp4.PaylBox{CueText: "A line"})

	boxDiffAfterEncodeAndDecode(t, vttc)
}

func TestWvtt(t *testing.T) {

	wvtt := mp4.NewWvttBox()
	vttC := &mp4.VttCBox{Config: "WEBVTT"}
	wvtt.AddChild(vttC)
	vlab := &mp4.VlabBox{SourceLabel: "Swedish news"}
	wvtt.AddChild(vlab)
	btrt := &mp4.BtrtBox{}
	wvtt.AddChild(btrt)
	if vttC != wvtt.VttC || vlab != wvtt.Vlab || btrt != wvtt.Btrt {
		t.Error("Pointers not set")
	}

	boxDiffAfterEncodeAndDecode(t, wvtt)
}

func TestVtte(t *testing.T) {
	vtte := &mp4.VtteBox{}
	boxDiffAfterEncodeAndDecode(t, vtte)
}

func TestVtta(t *testing.T) {
	vtta := &mp4.VttaBox{CueAdditionalText: "This is a comment"}
	boxDiffAfterEncodeAndDecode(t, vtta)
}

func TestVlab(t *testing.T) {
	vlab := &mp4.VlabBox{SourceLabel: "Swedish news"}
	boxDiffAfterEncodeAndDecode(t, vlab)
}

func TestVttC(t *testing.T) {
	vttC := &mp4.VttCBox{Config: "..."}
	boxDiffAfterEncodeAndDecode(t, vttC)
}
