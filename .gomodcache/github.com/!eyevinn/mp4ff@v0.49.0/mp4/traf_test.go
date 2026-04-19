package mp4_test

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/Eyevinn/mp4ff/mp4"
)

func createTestTrafBox() *mp4.TrafBox {
	traf := &mp4.TrafBox{}
	tfhd := &mp4.TfhdBox{}
	_ = traf.AddChild(tfhd)
	trun := mp4.CreateTrun(0)
	_ = traf.AddChild(trun)
	return traf
}

type testSamples struct {
	name    string
	samples []mp4.Sample
}

func TestTrafTrunWithoutOptimization(t *testing.T) {

	tests := []testSamples{
		{
			"audioSamples",
			[]mp4.Sample{
				{mp4.SyncSampleFlags, 1024, 234, 0},
				{mp4.SyncSampleFlags, 1024, 235, 0},
				{mp4.SyncSampleFlags, 1024, 235, 0},
			},
		},
		{
			"videoWithInitialSyncSample",
			[]mp4.Sample{
				{mp4.SyncSampleFlags, 1024, 234, 0},
				{mp4.NonSyncSampleFlags, 1024, 235, 0},
				{mp4.NonSyncSampleFlags, 1024, 235, 0},
			},
		},
		{
			"videoWithMultipleSyncSamplesAndCto",
			[]mp4.Sample{
				{mp4.SyncSampleFlags, 1024, 234, 0},
				{mp4.NonSyncSampleFlags, 1024, 235, 2048},
				{mp4.SyncSampleFlags, 1024, 235, -1024},
			},
		},
		{
			"singleSample",
			[]mp4.Sample{
				{mp4.SyncSampleFlags, 1024, 234, 0},
			},
		},
		{
			"sameSize",
			[]mp4.Sample{
				{mp4.SyncSampleFlags, 1024, 234, 0},
				{mp4.SyncSampleFlags, 1024, 234, 0},
			},
		},
	}

	// Without optimizations
	optimization := false
	for _, test := range tests {
		runEncodeDecode(t, test, optimization)
	}
	// With optimizations (smaller trun box)
	optimization = true
	for _, test := range tests {
		runEncodeDecode(t, test, optimization)
	}
}
func TestRemoveEncryptionBoxes(t *testing.T) {
	// Create a traf box with various child boxes
	traf := &mp4.TrafBox{}

	// Add boxes that should be removed
	saizBox := &mp4.SaizBox{Version: 0}
	saioBox := &mp4.SaioBox{Version: 0}
	sencBox := &mp4.SencBox{Version: 0}
	uuidSencBox := &mp4.UUIDBox{}
	_ = uuidSencBox.SetUUID(mp4.UUIDPiffSenc)
	uuidSencBox.Senc = &mp4.SencBox{Version: 0}
	uuidSencBox.Senc = &mp4.SencBox{Version: 0}
	sbgpSeigBox := &mp4.SbgpBox{GroupingType: "seig"}
	sgpdSeigBox := &mp4.SgpdBox{GroupingType: "seig"}
	boxesToBeRemoved := []mp4.Box{saizBox, saioBox, sencBox, uuidSencBox, sbgpSeigBox, sgpdSeigBox}

	// Add boxes that should NOT be removed
	tfhdBox := &mp4.TfhdBox{}
	trunBox := mp4.CreateTrun(0)

	// Add all boxes to traf
	_ = traf.AddChild(saizBox)
	_ = traf.AddChild(saioBox)
	_ = traf.AddChild(sencBox)
	_ = traf.AddChild(uuidSencBox)
	_ = traf.AddChild(sbgpSeigBox)
	_ = traf.AddChild(sgpdSeigBox)
	_ = traf.AddChild(tfhdBox)
	_ = traf.AddChild(trunBox)

	// Original children count
	originalChildrenCount := len(traf.Children)

	//
	expectedBytesRemoved := saizBox.Size() + saioBox.Size() + sencBox.Size() +
		uuidSencBox.Size() + sbgpSeigBox.Size() + sgpdSeigBox.Size()

	// Call RemoveEncryptionBoxes
	bytesRemoved := traf.RemoveEncryptionBoxes()

	// Verify expected number of bytes removed (6 boxes * mockBoxSize)
	if bytesRemoved != expectedBytesRemoved {
		t.Errorf("Expected %d bytes removed, got %d", expectedBytesRemoved, bytesRemoved)
	}

	// Verify correct number of children remain
	expectedRemainingChildren := originalChildrenCount - len(boxesToBeRemoved)
	if len(traf.Children) != expectedRemainingChildren {
		t.Errorf("Expected %d children remaining, got %d", expectedRemainingChildren, len(traf.Children))
	}

	// Verify encryption box pointers are nil
	if traf.Saiz != nil {
		t.Error("Saiz box was not removed")
	}
	if traf.Saio != nil {
		t.Error("Saio box was not removed")
	}
	if traf.Senc != nil {
		t.Error("Senc box was not removed")
	}
	if traf.Sbgp != nil && traf.Sbgp.GroupingType == "seig" {
		t.Error("Sbgp box with GroupingType 'seig' was not removed")
	}
	if traf.Sgpd != nil && traf.Sgpd.GroupingType == "seig" {
		t.Error("Sgpd box with GroupingType 'seig' was not removed")
	}

	// Verify Tfhd and Trun are still present
	if traf.Tfhd == nil {
		t.Error("Tfhd was incorrectly removed")
	}
	if traf.Trun == nil {
		t.Error("Trun was incorrectly removed")
	}
}

func runEncodeDecode(t *testing.T, test testSamples, withOptimization bool) {
	traf := createTestTrafBox()
	for _, s := range test.samples {
		traf.Trun.AddSample(s)
	}
	traf.Trun.DataOffset = 100 // Needs to be set. Value not important in test
	var buf bytes.Buffer
	if withOptimization {
		err := traf.OptimizeTfhdTrun()
		if err != nil {
			t.Error(err)
		}
	}
	err := traf.Encode(&buf)
	if err != nil {
		t.Error(err)
	}
	box, err := mp4.DecodeBox(0, &buf)
	if err != nil {
		t.Error(err)
	}
	outTraf := box.(*mp4.TrafBox)
	outTrun := outTraf.Trun
	trex := &mp4.TrexBox{}
	outTrun.AddSampleDefaultValues(outTraf.Tfhd, trex)
	outSamples := outTrun.Samples
	if !reflect.DeepEqual(outSamples, test.samples) {
		t.Errorf("Case %s optimization=%v failed. Got %v instead of %v",
			test.name, withOptimization, outSamples, test.samples)
	}
}
