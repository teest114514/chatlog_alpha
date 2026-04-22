package sei

import (
	"bytes"
	"testing"

	"github.com/Eyevinn/mp4ff/bits"
	"github.com/go-test/deep"
)

func TestSE1AVCCLock(t *testing.T) {
	cl := ClockTSAvc{
		CtType:             0,
		NuitFieldBasedFlag: false,
		CountingType:       0,
		NFrames:            5,
		Hours:              12,
		Minutes:            30,
		Seconds:            10,
		ClockTimeStampFlag: true,
		FullTimeStampFlag:  false,
		SecondsFlag:        true,
		MinutesFlag:        true,
		HoursFlag:          true,
		DiscontinuityFlag:  false,
		CntDroppedFlag:     false,
		TimeOffsetLength:   5,
		TimeOffsetValue:    -15,
	}
	jsonBytes, err := cl.MarshalJSON()
	if err != nil {
		t.Error(err)
	}
	wantedJSON := `{"time":"12:30:10:05","offset":-15}`
	if string(jsonBytes) != wantedJSON {
		t.Errorf("Got %s but wanted %s", jsonBytes, wantedJSON)
	}
	size := cl.NrBits()
	nrBytes := (size + 7) / 8
	sw := bits.NewFixedSliceWriter(nrBytes)
	cl.WriteToSliceWriter(sw)
	if sw.AccError() != nil {
		t.Error(sw.AccError())
	}
	sw.FlushBits()
	r := bytes.NewReader(sw.Bytes())
	rd := bits.NewReader(r)
	decClock := DecodeClockTSAvc(rd, cl.TimeOffsetLength)
	if diff := deep.Equal(cl, decClock); diff != nil {
		t.Error(diff)
	}
}
