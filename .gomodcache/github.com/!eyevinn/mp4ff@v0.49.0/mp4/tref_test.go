package mp4_test

import (
	"testing"

	"github.com/Eyevinn/mp4ff/mp4"
)

func TestTref(t *testing.T) {
	tref := mp4.TrefBox{}
	tref.AddChild(&mp4.TrefTypeBox{Name: "hint", TrackIDs: []uint32{1}})
	tref.AddChild(&mp4.TrefTypeBox{Name: "cdsc", TrackIDs: []uint32{2}})
	tref.AddChild(&mp4.TrefTypeBox{Name: "font", TrackIDs: []uint32{3}})
	tref.AddChild(&mp4.TrefTypeBox{Name: "hind", TrackIDs: []uint32{4}})
	tref.AddChild(&mp4.TrefTypeBox{Name: "vdep", TrackIDs: []uint32{5}})
	tref.AddChild(&mp4.TrefTypeBox{Name: "vdep", TrackIDs: []uint32{6}})
	tref.AddChild(&mp4.TrefTypeBox{Name: "vplx", TrackIDs: []uint32{7}})
	tref.AddChild(&mp4.TrefTypeBox{Name: "subt", TrackIDs: []uint32{8}})
	tref.AddChild(&mp4.TrefTypeBox{Name: "dpnd", TrackIDs: []uint32{9}})
	tref.AddChild(&mp4.TrefTypeBox{Name: "ipir", TrackIDs: []uint32{10}})
	tref.AddChild(&mp4.TrefTypeBox{Name: "mpod", TrackIDs: []uint32{11}})
	tref.AddChild(&mp4.TrefTypeBox{Name: "sync", TrackIDs: []uint32{12, 13}})
	boxDiffAfterEncodeAndDecode(t, &tref)
}
