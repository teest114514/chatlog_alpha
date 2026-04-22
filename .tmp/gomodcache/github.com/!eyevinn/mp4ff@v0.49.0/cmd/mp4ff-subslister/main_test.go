package main

import (
	"bytes"
	"testing"
)

var wantedWvttShort = `Track 1, timescale = 1000
Sample 1, pts=0, dur=6640
[vttc] size=52
  [sttg] size=18
   - settings: align:left
  [payl] size=26
   - cueText: "<c.magenta>...</c>"
Sample 2, pts=6640, dur=320
[vtte] size=8
Sample 3, pts=6960, dur=3040
[vttc] size=129
  [sttg] size=20
   - settings: align:center
  [payl] size=89
   - cueText: "<c.magenta>-Tout, tout, tout pourri,</c>\n<c.magenta>tout, tout, tout plaplat,</c>"
  [vsid] size=12
   - sourceID: 4068696550
Sample 4, pts=10000, dur=880
[vttc] size=129
  [sttg] size=20
   - settings: align:center
  [payl] size=89
   - cueText: "<c.magenta>-Tout, tout, tout pourri,</c>\n<c.magenta>tout, tout, tout plaplat,</c>"
  [vsid] size=12
   - sourceID: 4068696550
Sample 5, pts=10880, dur=320
[vtte] size=8
Sample 6, pts=11200, dur=3160
[vttc] size=127
  [sttg] size=20
   - settings: align:center
  [payl] size=99
   - cueText: "<c.magenta>Chien Pourri et Chaplapla,</c>\n<c.magenta>c'est moi, le chien, toi, le chat.</c>"
Sample 7, pts=14360, dur=320
[vtte] size=8
Sample 8, pts=14680, dur=5320
[vttc] size=131
  [sttg] size=20
   - settings: align:center
  [payl] size=91
   - cueText: "<c.magenta>Un ami, une poubelle,</c>\n<c.magenta>et pour nous, la vie est belle.</c>"
  [vsid] size=12
   - sourceID: 1833399447
`

var wantedMultiVttc = `Sample 1, pts=291054710760, dur=2560
[vttc] size=113
  [sttg] size=46
   - settings: align:middle line:61%,end position:49%
  [payl] size=59
   - cueText: "<c.white.bg_black>dans \"mulot\". Bravo, Agathe !</c>"
[vttc] size=117
  [sttg] size=46
   - settings: align:middle line:68%,end position:49%
  [payl] size=63
   - cueText: "<c.white.bg_black>Ouais ! Belle gosse ! Voici 2 M !</c>"
`

var wantedStppCombinedStart = `Track 1, timescale = 90000
  [stpp] size=43
   - dataReferenceIndex: 1
   - nameSpace: "http://www.w3.org/ns/ttml"
   - schemaLocation: ""
   - auxiliaryMimeTypes: ""
`

var wantedStppProgStart = `Track 1, timescale = 90000
  [stpp] size=64
   - dataReferenceIndex: 1
   - nameSpace: "http://www.w3.org/ns/ttml"
   - schemaLocation: ""
   - auxiliaryMimeTypes: ""
    [btrt] size=20
     - bufferSizeDB: 1592
     - maxBitrate: 2120
     - AvgBitrate: 2120
`

var wantedStppSamples = `Sample 1, pts=0, dur=540000
<?xml version="1.0" encoding="UTF-8"?>
<tt xmlns="http://www.w3.org/ns/ttml" xmlns:tts="http://www.w3.org/ns/ttml#styling" xml:lang="eng" ` +
	`xmlns:ttp="http://www.w3.org/ns/ttml#parameter" xmlns:ttm="http://www.w3.org/ns/ttml#metadata" ` +
	`xmlns:ebuttm="urn:ebu:tt:metadata" xmlns:ebutts="urn:ebu:tt:style" xml:space="default" ` +
	`ttp:timeBase="media" ttp:cellResolution="32 15">
  <head>
    <metadata/>
    <styling>
      <style xml:id="default" tts:fontStyle="normal" tts:fontFamily="sansSerif" tts:fontSize="100%" ` +
	`tts:lineHeight="normal" tts:textAlign="center" ebutts:linePadding="0.5c"/>
      <style xml:id="white_black" tts:backgroundColor="black" tts:color="white"/>
    </styling>
    <layout>
      <region xml:id="ttx_11" tts:origin="10% 84%" tts:extent="80% 15%" tts:overflow="visible"/>
      <region xml:id="ttx_9" tts:origin="10% 70%" tts:extent="80% 15%" tts:overflow="visible"/>
    </layout>
  </head>
  <body style="default">
    <div>
      <p begin="00:00:02.520" end="00:00:04.120" region="ttx_9" tts:textAlign="right">
        <span style="white_black">-Pourquoi ?</span>
      </p>
      <p begin="00:00:02.520" end="00:00:04.120" region="ttx_11" tts:textAlign="center">
        <span style="white_black">-J'ai...</span>
      </p>
      <p begin="00:00:04.520" end="00:00:06.600" region="ttx_9" tts:textAlign="center">
        <span style="white_black">J'ai un tas de trucs à faire.</span>
      </p>
      <p begin="00:00:04.520" end="00:00:06.600" region="ttx_11" tts:textAlign="center">
        <span style="white_black">-Non !</span>
      </p>
    </div>
  </body>
</tt>
`

var wantedStppCombined = wantedStppCombinedStart + wantedStppSamples
var wantedStppProgressive = wantedStppProgStart + wantedStppSamples

func TestSubsLister(t *testing.T) {

	testCases := []struct {
		desc        string
		args        []string
		expectedErr bool
		wanted      string
	}{
		{desc: "help", args: []string{appName, "-h"}, expectedErr: false},
		{desc: "unknown flag", args: []string{appName, "-x"}, expectedErr: true},
		{desc: "version", args: []string{appName, "-version"}, expectedErr: false},
		{desc: "no args", args: []string{appName}, expectedErr: true},
		{desc: "non-existent file", args: []string{appName, "notExisting.mp4"}, expectedErr: true},
		{desc: "bad file", args: []string{appName, "main.go"}, expectedErr: true},
		{desc: "no text track", args: []string{appName, "../../mp4/testdata/1.m4s"}, expectedErr: true},
		{
			desc:        "short wvtt",
			args:        []string{appName, "testdata/sample_short.ismt"},
			expectedErr: false,
			wanted:      wantedWvttShort,
		},
		{
			desc:        "multi vttc",
			args:        []string{appName, "testdata/multi_vttc.mp4"},
			expectedErr: false,
			wanted:      wantedMultiVttc,
		},
		{
			desc:        "stpp combined",
			args:        []string{appName, "testdata/stpp_combined.mp4"},
			expectedErr: false,
			wanted:      wantedStppCombined,
		},
		{
			desc:        "stpp progressive",
			args:        []string{appName, "testdata/stpp_prog.mp4"},
			expectedErr: false,
			wanted:      wantedStppProgressive,
		},
		{
			desc:        "max nr samples",
			args:        []string{appName, "-m", "1", "testdata/stpp_prog.mp4"},
			expectedErr: false,
		},
	}

	for _, c := range testCases {
		t.Run(c.desc, func(t *testing.T) {
			gotOut := bytes.Buffer{}
			err := run(c.args, &gotOut)
			if c.expectedErr {
				if err == nil {
					t.Error("expected error but got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %s", err)
				return
			}
			if c.wanted != "" {
				gotString := gotOut.String()
				if c.wanted != gotString {
					t.Errorf("expected %s, got %s", c.wanted, gotString)
				}
			}
		})
	}
}
