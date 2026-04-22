package mp4_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/Eyevinn/mp4ff/aac"
	"github.com/Eyevinn/mp4ff/mp4"
)

func TestStsd(t *testing.T) {
	stsd := mp4.StsdBox{}
	samplingFrequency := 48000
	asc := &aac.AudioSpecificConfig{
		ObjectType:           2,
		ChannelConfiguration: 2,
		SamplingFrequency:    samplingFrequency,
		ExtensionFrequency:   0,
		SBRPresentFlag:       false,
		PSPresentFlag:        false,
	}
	buf := &bytes.Buffer{}
	err := asc.Encode(buf)
	if err != nil {
		t.Error(err)
	}
	ascBytes := buf.Bytes()
	esds := mp4.CreateEsdsBox(ascBytes)
	mp4a := mp4.CreateAudioSampleEntryBox("mp4a",
		uint16(asc.ChannelConfiguration),
		16, uint16(samplingFrequency), esds)
	btrt := mp4.BtrtBox{
		BufferSizeDB: 1536,
		MaxBitrate:   96000,
		AvgBitrate:   96000,
	}
	mp4a.AddChild(&btrt)
	stsd.AddChild(mp4a)
	if len(stsd.Children) != 1 {
		t.Error("Expected one child")
	}
	if stsd.Mp4a == nil {
		t.Error("Expected mp4a child")
	}
	gb := stsd.GetBtrt()
	if gb == nil {
		t.Error("Expected btrt")
	} else {
		if *gb != btrt {
			t.Errorf("Got btrt %v, expected %v", *gb, btrt)
		}
	}
}

func TestStsdEncodeDecode(t *testing.T) {
	stsd := &mp4.StsdBox{}
	evte := &mp4.EvteBox{}
	stsd.AddChild(evte)
	boxDiffAfterEncodeAndDecode(t, stsd)
	b, err := stsd.GetSampleDescription(0)
	if err != nil {
		t.Error(err)
	}
	if b != evte {
		t.Errorf("Expected %v, got %v", evte, b)
	}
	b, err = stsd.GetSampleDescription(1)
	if err == nil {
		t.Errorf("Expected error, got %v", b)
	}
	btrt := stsd.GetBtrt()
	if btrt != nil {
		t.Errorf("Expected nil, got %v", btrt)
	}
}

func TestStsdVP9(t *testing.T) {
	hexData := "" +
		"000000a87374736400000000000000010000009876703039000000000000" +
		"000100000000000000000000000000000000050002d00048000000480000" +
		"000000000001184c61766336312e31392e313030206c69627670782d7670" +
		"39000000000000000018ffff000000147670634301000000001f80020202" +
		"00000000000a6669656c0100000000107061737000000001000000010000" +
		"001462747274000000000010152200101522"

	binData, err := hex.DecodeString(hexData)
	if err != nil {
		t.Error(err)
	}

	cmpAfterDecodeEncodeBox(t, binData)
}
