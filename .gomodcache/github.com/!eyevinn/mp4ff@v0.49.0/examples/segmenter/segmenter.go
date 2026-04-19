package main

import (
	"fmt"
	"io"

	"github.com/Eyevinn/mp4ff/mp4"
)

// Segmenter - segment the progressive inFIle
type Segmenter struct {
	inFile *mp4.File
	tracks []*Track
	nrSegs int //  target number of segments
}

// Track - media track defined by inTrak
type Track struct {
	trackType string
	inTrak    *mp4.TrakBox
	timeScale uint32
	trackID   uint32 // trackID in segmented output
	lang      string
	segments  []sampleInterval
}

// NewSegmenter - create a Segmenter from inFile and fill in track information
func NewSegmenter(inFile *mp4.File) (*Segmenter, error) {
	if inFile.IsFragmented() {
		return nil, fmt.Errorf("segmented input file not supported")
	}
	s := Segmenter{inFile: inFile}
	traks := inFile.Moov.Traks
	for _, trak := range traks {
		track := &Track{trackType: "", lang: ""}
		switch hdlrType := trak.Mdia.Hdlr.HandlerType; hdlrType {
		case "vide":
			track.trackType = "video"
		case "soun":
			track.trackType = "audio"
		default:
			return nil, fmt.Errorf("hdlr typpe %q not supported", hdlrType)
		}
		track.lang = trak.Mdia.Mdhd.GetLanguage()
		if trak.Mdia.Elng != nil {
			track.lang = trak.Mdia.Elng.Language
		}
		track.inTrak = trak
		track.timeScale = trak.Mdia.Mdhd.Timescale
		s.tracks = append(s.tracks, track)
	}
	return &s, nil
}

// SetTargetSegmentation - set segment start points
func (s *Segmenter) SetTargetSegmentation(syncTimescale uint32, segStarts []syncPoint) error {
	var err error
	for i := range s.tracks {
		s.tracks[i].segments, err = getSegmentIntervals(syncTimescale, segStarts, s.tracks[i].inTrak)
		if err != nil {
			return err
		}
	}
	s.nrSegs = len(segStarts)
	return nil
}

// MakeInitSegments - initialized and return init segments for all the tracks
func (s *Segmenter) MakeInitSegments() ([]*mp4.InitSegment, error) {
	var inits []*mp4.InitSegment
	for _, tr := range s.tracks {
		init := mp4.CreateEmptyInit()
		init.Moov.Mvhd.Timescale = s.inFile.Moov.Mvhd.Timescale
		inMovieDuration := s.inFile.Moov.Mvhd.Duration
		init.Moov.Mvex.AddChild(&mp4.MehdBox{FragmentDuration: int64(inMovieDuration)})
		init.AddEmptyTrack(tr.timeScale, tr.trackType, tr.lang)
		outTrak := init.Moov.Trak
		tr.trackID = outTrak.Tkhd.TrackID

		inStsd := tr.inTrak.Mdia.Minf.Stbl.Stsd
		outStsd := outTrak.Mdia.Minf.Stbl.Stsd
		switch tr.trackType {
		case "audio":
			if inStsd.Mp4a != nil {
				outStsd.AddChild(inStsd.Mp4a)
			} else if inStsd.AC3 != nil {
				outStsd.AddChild(inStsd.AC3)
			} else if inStsd.EC3 != nil {
				outStsd.AddChild(inStsd.EC3)
			}
		case "video":
			if inStsd.AvcX != nil {
				outStsd.AddChild(inStsd.AvcX)
			} else if inStsd.HvcX != nil {
				outStsd.AddChild(inStsd.HvcX)
			}
		default:
			return nil, fmt.Errorf("unsupported tracktype: %s", tr.trackType)
		}
		inits = append(inits, init)
	}
	return inits, nil
}

// MakeMuxedInitSegment - initialized and return one init segments for all the tracks
func (s *Segmenter) MakeMuxedInitSegment() (*mp4.InitSegment, error) {
	init := mp4.CreateEmptyInit()
	inMovieDuration := s.inFile.Moov.Mvhd.Duration
	init.Moov.Mvex.AddChild(&mp4.MehdBox{FragmentDuration: int64(inMovieDuration)})
	for _, tr := range s.tracks {
		init.AddEmptyTrack(tr.timeScale, tr.trackType, tr.lang)
		outTrak := init.Moov.Traks[len(init.Moov.Traks)-1]
		tr.trackID = outTrak.Tkhd.TrackID
		inStsd := tr.inTrak.Mdia.Minf.Stbl.Stsd
		outStsd := outTrak.Mdia.Minf.Stbl.Stsd
		switch tr.trackType {
		case "audio":
			if inStsd.Mp4a != nil {
				outStsd.AddChild(inStsd.Mp4a)
			} else if inStsd.AC3 != nil {
				outStsd.AddChild(inStsd.AC3)
			} else if inStsd.EC3 != nil {
				outStsd.AddChild(inStsd.EC3)
			}
		case "video":
			if inStsd.AvcX != nil {
				outStsd.AddChild(inStsd.AvcX)
			} else if inStsd.HvcX != nil {
				outStsd.AddChild(inStsd.HvcX)
			}
		default:
			return nil, fmt.Errorf("unsupported tracktype: %s", tr.trackType)
		}
	}

	return init, nil
}

// GetFullSamplesForInterval - get slice of fullsamples with numbers startSampleNr to endSampleNr (inclusive)
func (s *Segmenter) GetFullSamplesForInterval(mp4f *mp4.File, tr *Track, startSampleNr, endSampleNr uint32,
	rs io.ReadSeeker) ([]mp4.FullSample, error) {
	stbl := tr.inTrak.Mdia.Minf.Stbl
	samples := make([]mp4.FullSample, 0, endSampleNr-startSampleNr+1)
	mdat := mp4f.Mdat
	mdatPayloadStart := mdat.PayloadAbsoluteOffset()
	for sampleNr := startSampleNr; sampleNr <= endSampleNr; sampleNr++ {
		chunkNr, sampleNrAtChunkStart, err := stbl.Stsc.ChunkNrFromSampleNr(int(sampleNr))
		if err != nil {
			return nil, err
		}
		var offset int64
		if stbl.Stco != nil {
			offset = int64(stbl.Stco.ChunkOffset[chunkNr-1])
		} else if stbl.Co64 != nil {
			offset = int64(stbl.Co64.ChunkOffset[chunkNr-1])
		}

		for sNr := sampleNrAtChunkStart; sNr < int(sampleNr); sNr++ {
			offset += int64(stbl.Stsz.GetSampleSize(sNr))
		}
		size := stbl.Stsz.GetSampleSize(int(sampleNr))
		decTime, dur := stbl.Stts.GetDecodeTime(sampleNr)
		var cto int32 = 0
		if stbl.Ctts != nil {
			cto = stbl.Ctts.GetCompositionTimeOffset(sampleNr)
		}
		var sampleData []byte
		// Next find bytes as slice in mdat
		if mdat.GetLazyDataSize() > 0 {
			_, err := rs.Seek(offset, io.SeekStart)
			if err != nil {
				return nil, err
			}
			sampleData = make([]byte, size)
			_, err = io.ReadFull(rs, sampleData)
			if err != nil {
				return nil, err
			}
		} else {
			offsetInMdatData := uint64(offset) - mdatPayloadStart
			sampleData = mdat.Data[offsetInMdatData : offsetInMdatData+uint64(size)]
		}

		//presTime := uint64(int64(decTime) + int64(cto))
		//One can either segment on presentationTime or DecodeTime
		//presTimeMs := presTime * 1000 / uint64(tr.timeScale)
		sc := mp4.FullSample{
			Sample: mp4.Sample{
				Flags:                 TranslateSampleFlagsForFragment(stbl, sampleNr),
				Size:                  size,
				Dur:                   dur,
				CompositionTimeOffset: cto,
			},
			DecodeTime: decTime,
			Data:       sampleData,
		}

		//fmt.Printf("Sample %d times %d %d, sync %v, offset %d, size %d\n", sampleNr, decTime, cto, isSync, offset, size)
		samples = append(samples, sc)
	}
	return samples, nil
}

// GetSamplesForInterval - get slice of samples with numbers startSampleNr to endSampleNr (inclusive)
func (s *Segmenter) GetSamplesForInterval(mp4f *mp4.File, trak *mp4.TrakBox, startSampleNr, endSampleNr uint32) ([]mp4.Sample, error) {
	stbl := trak.Mdia.Minf.Stbl
	samples := make([]mp4.Sample, 0, endSampleNr-startSampleNr+1)
	for sampleNr := startSampleNr; sampleNr <= endSampleNr; sampleNr++ {
		size := stbl.Stsz.GetSampleSize(int(sampleNr))
		dur := stbl.Stts.GetDur(sampleNr)
		var cto int32 = 0
		if stbl.Ctts != nil {
			cto = stbl.Ctts.GetCompositionTimeOffset(sampleNr)
		}

		//presTime := uint64(int64(decTime) + int64(cto))
		//One can either segment on presentationTime or DecodeTime
		//presTimeMs := presTime * 1000 / uint64(trak.timeScale)
		sc := mp4.Sample{
			Flags:                 TranslateSampleFlagsForFragment(stbl, sampleNr),
			Size:                  size,
			Dur:                   dur,
			CompositionTimeOffset: cto,
		}

		//fmt.Printf("Sample %d times %d %d, sync %v, offset %d, size %d\n", sampleNr, decTime, cto, isSync, offset, size)
		samples = append(samples, sc)
	}
	return samples, nil
}

// TranslateSampleFlagsForFragment - translate sample flags from stss and sdtp to what is needed in trun
func TranslateSampleFlagsForFragment(stbl *mp4.StblBox, sampleNr uint32) (flags uint32) {
	var sampleFlags mp4.SampleFlags
	if stbl.Stss != nil {
		isSync := stbl.Stss.IsSyncSample(uint32(sampleNr))
		sampleFlags.SampleIsNonSync = !isSync
		if isSync {
			sampleFlags.SampleDependsOn = 2 //2 == does not depend on others (I-picture). May be overridden by sdtp entry
		}
	}
	if stbl.Sdtp != nil {
		entry := stbl.Sdtp.Entries[uint32(sampleNr)-1] // table starts at 0, but sampleNr is one-based
		sampleFlags.IsLeading = entry.IsLeading()
		sampleFlags.SampleDependsOn = entry.SampleDependsOn()
		sampleFlags.SampleHasRedundancy = entry.SampleHasRedundancy()
		sampleFlags.SampleIsDependedOn = entry.SampleIsDependedOn()
	}
	return sampleFlags.Encode()
}
