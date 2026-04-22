package main

import (
	"fmt"
	"io"
	"os"

	"github.com/Eyevinn/mp4ff/mp4"
)

func makeSingleTrackSegments(segmenter *Segmenter, parsedMp4 *mp4.File, rs io.ReadSeeker, outFilePath string) error {
	fileNameMap := map[string]string{"video": "_v", "audio": "_a"}
	inits, err := segmenter.MakeInitSegments()
	if err != nil {
		return err
	}
	for _, init := range inits {
		trackID := init.Moov.Trak.Tkhd.TrackID
		outPath := fmt.Sprintf("%s%s%d_init.mp4", outFilePath, fileNameMap[init.GetMediaType()], trackID)
		err = mp4.WriteToFile(init, outPath)
		if err != nil {
			return err
		}
		fmt.Printf("Generated %s\n", outPath)
	}

	segNr := 1
	for {
		for _, tr := range segmenter.tracks {
			mediaType := tr.trackType
			startSampleNr, endSampleNr := tr.segments[segNr-1].startNr, tr.segments[segNr-1].endNr
			fmt.Printf("%s: %d-%d\n", tr.trackType, startSampleNr, endSampleNr)
			fullSamples, err := segmenter.GetFullSamplesForInterval(parsedMp4, tr, startSampleNr, endSampleNr, rs)
			if len(fullSamples) == 0 {
				fmt.Printf("No more samples for %s\n", mediaType)
				continue
			}
			if err != nil {
				return err
			}
			seg := mp4.NewMediaSegment()
			frag, err := mp4.CreateFragment(uint32(segNr), tr.trackID)
			if err != nil {
				return err
			}
			seg.AddFragment(frag)

			for _, fullSample := range fullSamples {
				err = frag.AddFullSampleToTrack(fullSample, tr.trackID)
				if err != nil {
					return err
				}
			}
			outPath := fmt.Sprintf("%s%s%d_%d.m4s", outFilePath, fileNameMap[mediaType], tr.trackID, segNr)
			err = mp4.WriteToFile(seg, outPath)
			if err != nil {
				return err
			}
			fmt.Printf("Generated %s\n", outPath)
		}
		segNr++
		if segNr > segmenter.nrSegs {
			break
		}
	}
	return nil
}

func makeSingleTrackSegmentsLazyWrite(segmenter *Segmenter, parsedMp4 *mp4.File, rs io.ReadSeeker, outFilePath string) error {
	fileNameMap := map[string]string{"video": "_v", "audio": "_a"}
	inits, err := segmenter.MakeInitSegments()
	if err != nil {
		return err
	}
	for _, init := range inits {
		trackID := init.Moov.Trak.Tkhd.TrackID
		outPath := fmt.Sprintf("%s%s%d_init.mp4", outFilePath, fileNameMap[init.GetMediaType()], trackID)
		err = mp4.WriteToFile(init, outPath)
		if err != nil {
			return err
		}
		fmt.Printf("Generated %s\n", outPath)
	}

	segNr := 1
	for {
		for _, tr := range segmenter.tracks {
			mediaType := tr.trackType
			startSampleNr, endSampleNr := tr.segments[segNr-1].startNr, tr.segments[segNr-1].endNr
			fmt.Printf("%s: %d-%d\n", tr.trackType, startSampleNr, endSampleNr)
			samples, err := segmenter.GetSamplesForInterval(parsedMp4, tr.inTrak, startSampleNr, endSampleNr)
			if len(samples) == 0 {
				fmt.Printf("No more samples for %s\n", mediaType)
				continue
			}
			if err != nil {
				return err
			}
			seg := mp4.NewMediaSegment()
			frag, err := mp4.CreateFragment(uint32(segNr), tr.trackID)
			if err != nil {
				return err
			}
			seg.AddFragment(frag)
			baseMediaDecodeTime, _ := tr.inTrak.Mdia.Minf.Stbl.Stts.GetDecodeTime(startSampleNr)
			for _, sample := range samples {
				err = frag.AddSampleToTrack(sample, tr.trackID, baseMediaDecodeTime)
				if err != nil {
					return err
				}
			}
			outPath := fmt.Sprintf("%s%s%d_%d.m4s", outFilePath, fileNameMap[mediaType], tr.trackID, segNr)
			ofh, err := os.Create(outPath)
			if err != nil {
				return err
			}
			defer ofh.Close()
			err = seg.Encode(ofh)
			if err != nil {
				return err
			}
			// Also write media data
			err = copyMediaData(tr.inTrak, startSampleNr, endSampleNr, rs, ofh)
			if err != nil {
				return err
			}
			fmt.Printf("Generated %s\n", outPath)
		}
		segNr++
		if segNr > segmenter.nrSegs {
			break
		}
	}
	return nil
}

func makeMultiTrackSegments(segmenter *Segmenter, parsedMp4 *mp4.File, rs io.ReadSeeker, outFilePath string) error {
	init, err := segmenter.MakeMuxedInitSegment()
	if err != nil {
		return err
	}
	outPath := fmt.Sprintf("%s_init.mp4", outFilePath)
	err = mp4.WriteToFile(init, outPath)
	if err != nil {
		return err
	}
	fmt.Printf("Generated %s\n", outPath)
	var trackIDs []uint32
	for _, trak := range init.Moov.Traks {
		trackIDs = append(trackIDs, trak.Tkhd.TrackID)
	}

	segNr := 1
	for {
		seg := mp4.NewMediaSegment()
		frag, err := mp4.CreateMultiTrackFragment(uint32(segNr), trackIDs)
		if err != nil {
			return err
		}
		seg.AddFragment(frag)

		for _, tr := range segmenter.tracks {
			startSampleNr, endSampleNr := tr.segments[segNr-1].startNr, tr.segments[segNr-1].endNr
			fmt.Printf("%s: %d-%d\n", tr.trackType, startSampleNr, endSampleNr)
			fullSamples, err := segmenter.GetFullSamplesForInterval(parsedMp4, tr, startSampleNr, endSampleNr, rs)
			if len(fullSamples) == 0 {
				continue
			}
			if err != nil {
				return err
			}
			for _, sample := range fullSamples {
				err = frag.AddFullSampleToTrack(sample, tr.trackID)
				if err != nil {
					return err
				}
			}
		}
		outPath := fmt.Sprintf("%s_media_%d.m4s", outFilePath, segNr)
		err = mp4.WriteToFile(seg, outPath)
		if err != nil {
			return err
		}
		fmt.Printf("Generated %s\n", outPath)
		segNr++
		if segNr > segmenter.nrSegs {
			break
		}
	}
	return nil
}

type syncPoint struct {
	sampleNr   uint32
	decodeTime uint64
	presTime   uint64
}

func getSegmentStartsFromVideo(parsedMp4 *mp4.File, segDurMS uint32) (timeScale uint32, syncPoints []syncPoint) {
	var refTrak *mp4.TrakBox
	for _, trak := range parsedMp4.Moov.Traks {
		hdlrType := trak.Mdia.Hdlr.HandlerType
		if hdlrType == "vide" {
			refTrak = trak
			break
		}
	}
	if refTrak == nil {
		panic("Cannot handle case with no video track yet")
	}
	timeScale = refTrak.Mdia.Mdhd.Timescale
	stts := refTrak.Mdia.Minf.Stbl.Stts
	stss := refTrak.Mdia.Minf.Stbl.Stss
	ctts := refTrak.Mdia.Minf.Stbl.Ctts
	syncPoints = make([]syncPoint, 0, stss.EntryCount())
	var segmentStep = uint32(uint64(segDurMS) * uint64(timeScale) / 1000)
	var nextSegmentStart uint32 = 0
	for _, sampleNr := range stss.SampleNumber {
		decodeTime, _ := stts.GetDecodeTime(sampleNr)
		presTime := int64(decodeTime)
		if ctts != nil {
			presTime += int64(ctts.GetCompositionTimeOffset(sampleNr))
		}
		if presTime >= int64(nextSegmentStart) {
			syncPoints = append(syncPoints, syncPoint{sampleNr, decodeTime, uint64(presTime)})
			nextSegmentStart += segmentStep
		}
	}
	return timeScale, syncPoints
}

type sampleInterval struct {
	startNr uint32
	endNr   uint32 // included in interval
}

func getSegmentIntervals(syncTimescale uint32, syncPoints []syncPoint, trak *mp4.TrakBox) ([]sampleInterval, error) {
	totNrSamples := trak.Mdia.Minf.Stbl.Stsz.SampleNumber
	var startSampleNr uint32 = 1
	var nextStartSampleNr uint32 = 0
	var endSampleNr uint32
	var err error

	sampleIntervals := make([]sampleInterval, len(syncPoints))

	for i := range syncPoints {
		if nextStartSampleNr != 0 {
			startSampleNr = nextStartSampleNr
		}
		if i == len(syncPoints)-1 {
			endSampleNr = totNrSamples - 1
		} else {
			nextSyncStart := syncPoints[i+1].decodeTime
			nextStartTime := nextSyncStart * uint64(trak.Mdia.Mdhd.Timescale) / uint64(syncTimescale)
			nextStartSampleNr, err = trak.Mdia.Minf.Stbl.Stts.GetSampleNrAtTime(nextStartTime)
			if err != nil {
				return nil, err
			}
			endSampleNr = nextStartSampleNr - 1
		}
		sampleIntervals[i] = sampleInterval{startSampleNr, endSampleNr}
	}
	fmt.Printf("Sample intervals: %v\n", sampleIntervals)
	return sampleIntervals, nil
}

func copyMediaData(trak *mp4.TrakBox, startSampleNr, endSampleNr uint32, rs io.ReadSeeker, w io.Writer) error {
	stbl := trak.Mdia.Minf.Stbl
	chunks, err := stbl.Stsc.GetContainingChunks(startSampleNr, endSampleNr)
	if err != nil {
		return err
	}
	var offset uint64
	var startNr, endNr uint32
	for i, chunk := range chunks {
		if stbl.Co64 != nil {
			offset = stbl.Co64.ChunkOffset[chunk.ChunkNr-1]
		} else if stbl.Stco != nil {
			offset = uint64(stbl.Stco.ChunkOffset[chunk.ChunkNr-1])
		}
		startNr = chunk.StartSampleNr
		endNr = startNr + chunk.NrSamples - 1
		if i == 0 {
			for sNr := chunk.StartSampleNr; sNr < startSampleNr; sNr++ {
				offset += uint64(stbl.Stsz.GetSampleSize(int(sNr)))
			}
			startNr = startSampleNr
		}

		if i == len(chunks)-1 {
			endNr = endSampleNr
		}
		var size int64
		for sNr := startNr; sNr <= endNr; sNr++ {
			size += int64(stbl.Stsz.GetSampleSize(int(sNr)))
		}
		_, err := rs.Seek(int64(offset), io.SeekStart)
		if err != nil {
			return err
		}
		n, err := io.CopyN(w, rs, size)
		if err != nil {
			return err
		}
		if n != size {
			return fmt.Errorf("copied %d bytes instead of %d", n, size)
		}
	}

	return nil
}
