package mp4_test

import (
	"bytes"
	"testing"

	"github.com/Eyevinn/mp4ff/bits"
	"github.com/Eyevinn/mp4ff/mp4"
	"github.com/go-test/deep"
)

func TestSencDirectValues(t *testing.T) {
	iv8 := mp4.InitializationVector("12345678")
	iv16 := mp4.InitializationVector("0123456789abcdef")
	cases := []struct {
		desc            string
		senc            *mp4.SencBox
		perSampleIVSize byte
	}{
		{
			desc: "No perSampleIVs",
			senc: &mp4.SencBox{
				Version:     0,
				Flags:       0,
				SampleCount: 431, // No perSampleIVs
			},
			perSampleIVSize: 0,
		},
		{
			desc: "perSampleIVSize 8",
			senc: &mp4.SencBox{
				Version:     0,
				Flags:       0,
				SampleCount: 1,
				IVs:         []mp4.InitializationVector{iv8},
				SubSamples:  [][]mp4.SubSamplePattern{{{10, 1000}}},
			},
			perSampleIVSize: 8,
		},
		{
			desc: "perSampleIVSize 16",
			senc: &mp4.SencBox{
				Version:     0,
				Flags:       0,
				SampleCount: 1,
				IVs:         []mp4.InitializationVector{iv16},
				SubSamples:  [][]mp4.SubSamplePattern{{{10, 1000}, {20, 2000}}},
			},
			perSampleIVSize: 16,
		},
		{
			desc: "perSampleIVSize 16, 2 subsamples",
			senc: &mp4.SencBox{
				Version:     0,
				Flags:       0,
				SampleCount: 2,
				IVs:         []mp4.InitializationVector{iv16, iv16},
				SubSamples:  [][]mp4.SubSamplePattern{{{10, 1000}}, {{20, 2000}}},
			},
			perSampleIVSize: 16,
		},
	}

	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			c.senc.SetPerSampleIVSize(c.perSampleIVSize)
			sencDiffAfterEncodeAndDecode(t, c.senc, 0)
			sencDiffAfterEncodeAndDecode(t, c.senc, c.perSampleIVSize)
		})
	}
}

func sencDiffAfterEncodeAndDecode(t *testing.T, senc *mp4.SencBox, perSampleIVSize byte) {
	t.Helper()
	buf := bytes.Buffer{}
	err := senc.Encode(&buf)
	if err != nil {
		t.Error(err)
	}

	boxDec, err := mp4.DecodeBox(0, &buf)
	if err != nil {
		t.Error(err)
	}
	decSenc := boxDec.(*mp4.SencBox)
	var saizBox *mp4.SaizBox

	if decSenc.ReadButNotParsed() {
		err = decSenc.ParseReadBox(perSampleIVSize, saizBox)
		if err != nil {
			t.Error(err)
		}
	}

	if diff := deep.Equal(decSenc, senc); diff != nil {
		t.Error(diff)
	}
}

func TestAddSamples(t *testing.T) {
	iv0 := mp4.InitializationVector("")
	iv8 := mp4.InitializationVector("01234567")
	iv16 := mp4.InitializationVector("0123456789abcdef")

	senc := mp4.CreateSencBox()
	err := senc.AddSample(mp4.SencSample{iv0, []mp4.SubSamplePattern{{10, 1000}}})
	assertNoError(t, err)
	sencDiffAfterEncodeAndDecode(t, senc, 0)

	senc = mp4.CreateSencBox()
	err = senc.AddSample(mp4.SencSample{iv8, nil})
	assertNoError(t, err)
	sencDiffAfterEncodeAndDecode(t, senc, 0)
	sencDiffAfterEncodeAndDecode(t, senc, 8)

	senc = mp4.CreateSencBox()
	err = senc.AddSample(mp4.SencSample{iv8, []mp4.SubSamplePattern{{10, 1000}}})
	assertNoError(t, err)
	sencDiffAfterEncodeAndDecode(t, senc, 0)
	sencDiffAfterEncodeAndDecode(t, senc, 8)

	senc = mp4.CreateSencBox()
	err = senc.AddSample(mp4.SencSample{iv8, []mp4.SubSamplePattern{{10, 1000}}})
	assertNoError(t, err)
	sencDiffAfterEncodeAndDecode(t, senc, 0)
	sencDiffAfterEncodeAndDecode(t, senc, 8)

	senc = mp4.CreateSencBox()
	err = senc.AddSample(mp4.SencSample{iv16, []mp4.SubSamplePattern{{10, 1000}, {20, 2000}}})
	assertNoError(t, err)
	sencDiffAfterEncodeAndDecode(t, senc, 0)
	sencDiffAfterEncodeAndDecode(t, senc, 16)

	senc = mp4.CreateSencBox()
	err = senc.AddSample(mp4.SencSample{iv16, []mp4.SubSamplePattern{{10, 1000}}})
	assertNoError(t, err)
	err = senc.AddSample(mp4.SencSample{iv16, []mp4.SubSamplePattern{{20, 2000}}})
	assertNoError(t, err)
	sencDiffAfterEncodeAndDecode(t, senc, 0)
	sencDiffAfterEncodeAndDecode(t, senc, 16)

	senc = mp4.CreateSencBox()
	err = senc.AddSample(mp4.SencSample{iv16, []mp4.SubSamplePattern{{10, 1000}}})
	assertNoError(t, err)
	err = senc.AddSample(mp4.SencSample{iv8, []mp4.SubSamplePattern{{20, 2000}}})
	assertError(t, err, "Should have got error due to different iv size")
}

// TestImplicitIVSize tests that the implicit IV size is correctly calculated (perSampleIVSize != 0)
func TestImplicitIVSize(t *testing.T) {
	testCases := []struct {
		inputFile        string
		expectedSencSize int
	}{
		{inputFile: "testdata/2xSencNoMdat.mp4", expectedSencSize: 2248},
	}

	for _, tc := range testCases {
		// Read the file
		m, err := mp4.ReadMP4File(tc.inputFile)
		if err != nil {
			t.Error(err)
		}
		frag := m.Segments[0].Fragments[0]
		senc := frag.Moof.Traf.Senc
		if int(senc.Size()) != tc.expectedSencSize {
			t.Errorf("Expected senc size %d, got %d", tc.expectedSencSize, senc.Size())
		}
	}
}

func TestBadSencData(t *testing.T) {
	// raw senc box with version > 2 */
	cases := []struct {
		desc string
		raw  []byte
		err  string
	}{
		{
			desc: "too short",
			raw:  []byte{0x00, 0x00, 0x00, 0x0f, 's', 'e', 'n', 'c', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			err:  "decode senc pos 0: box size 15 less than min size 16",
		},
		{
			desc: "v1 not supported",
			raw:  []byte{0x00, 0x00, 0x00, 0x10, 's', 'e', 'n', 'c', 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			err:  "decode senc pos 0: version 1 not supported",
		},
		{
			desc: "too short for subsample encryption",
			raw:  []byte{0x00, 0x00, 0x00, 0x10, 's', 'e', 'n', 'c', 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0xff},
			err:  "decode senc pos 0: box size 16 too small for 255 samples and subSampleEncryption",
		},
	}

	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			buf := bytes.NewBuffer(c.raw)
			_, err := mp4.DecodeBox(0, buf)
			if err == nil {
				t.Errorf("expected error %q, but got nil", c.err)
			}
			if err.Error() != c.err {
				t.Errorf("expected error %q, got %q", c.err, err.Error())
			}

			sr := bits.NewFixedSliceReader(c.raw)
			_, err = mp4.DecodeBoxSR(0, sr)
			if err == nil {
				t.Errorf("expected error %q, but got nil", c.err)
			}
			if err.Error() != c.err {
				t.Errorf("expected error %q, got %q", c.err, err.Error())
			}
		})
	}
}
