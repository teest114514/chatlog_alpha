package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/Eyevinn/mp4ff/internal"
	"github.com/Eyevinn/mp4ff/mp4"
)

const (
	appName = "mp4ff-crop"
)

var usg = `%s crops a (progressive) mp4 file to just before a sync frame after specified number of milliseconds.
The goal is to leave the file structure intact except for cropping of samples and
moving mdat to the end of the file, if not already there.

Usage of %s:
`

type options struct {
	durationMS uint
	version    bool
}

func parseOptions(fs *flag.FlagSet, args []string) (*options, error) {
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, usg, appName, appName)
		fmt.Fprintf(os.Stderr, "\n%s [options] <inFile> <outFile>\n\noptions:\n", appName)
		fs.PrintDefaults()
	}

	opts := options{}

	fs.UintVar(&opts.durationMS, "d", 1000, "Duration in milliseconds")
	fs.BoolVar(&opts.version, "version", false, "Get mp4ff version")

	err := fs.Parse(args[1:])
	return &opts, err
}

func main() {
	if err := run(os.Args, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet(appName, flag.ContinueOnError)
	o, err := parseOptions(fs, args)

	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	if o.version {
		fmt.Fprintf(stdout, "%s %s\n", appName, internal.GetVersion())
		return nil
	}

	if len(fs.Args()) != 2 {
		fs.Usage()
		return fmt.Errorf("must specify inFile and outFile")
	}

	if o.durationMS == 0 {
		fs.Usage()
		return fmt.Errorf("error: duration must be larger than 0: %dms", o.durationMS)
	}

	inFilePath := fs.Arg(0)
	outFilePath := fs.Arg(1)

	ifh, err := os.Open(inFilePath)
	if err != nil {
		return fmt.Errorf("error opening input file: %w", err)
	}
	defer ifh.Close()
	parsedMp4, err := mp4.DecodeFile(ifh, mp4.WithDecodeMode(mp4.DecModeLazyMdat))
	if err != nil {
		return fmt.Errorf("error decoding mp4 file: %w", err)
	}

	ofh, err := os.Create(outFilePath)
	if err != nil {
		return fmt.Errorf("error creating output file: %w", err)
	}
	defer ofh.Close()

	err = cropMP4(parsedMp4, int(o.durationMS), ofh, ifh)
	if err != nil {
		return fmt.Errorf("error cropping mp4 file: %w", err)
	}
	return nil
}

func cropMP4(inMP4 *mp4.File, durationMS int, w io.Writer, ifh io.ReadSeeker) error {
	if inMP4.IsFragmented() {
		return fmt.Errorf("only progressive files are supported")
	}
	inMoov := inMP4.Moov
	inMoovDur := float64(inMoov.Mvhd.Duration) / float64(inMoov.Mvhd.Timescale)
	fmt.Printf("input moov duration = %.3fs\n", inMoovDur)

	endTime, endTimescale, err := findEndTime(inMoov, durationMS)
	if err != nil {
		return err
	}

	err = cropToTime(inMP4, endTime, endTimescale, w, ifh)
	if err != nil {
		return err
	}
	fmt.Printf("wrote output with endTime=%dms\n", (endTime*1000)/endTimescale)
	return nil

}

// findEndTime - find closest video sync frame, or audio frame if no video
func findEndTime(moov *mp4.MoovBox, durationMS int) (endTime, endTimescale uint64, err error) {
	var syncTrak *mp4.TrakBox
	for _, trak := range moov.Traks {
		if trak.Mdia.Hdlr.HandlerType == "vide" {
			syncTrak = trak
			break
		}
	}
	if syncTrak == nil {
		for _, trak := range moov.Traks {
			if trak.Mdia.Hdlr.HandlerType == "soun" {
				syncTrak = trak
				fmt.Printf("Uses audio track %d for endtime\n", trak.Tkhd.TrackID)
				break
			}
		}
	}
	if syncTrak == nil {
		return 0, 0, fmt.Errorf("did not find any video or audio track")
	}

	//trakDur := float64(trak.Tkhd.Duration) / float64(moov.Mvhd.Timescale)
	//fmt.Printf("video trak %d duration = %.3fs\n", trak.Tkhd.TrackID, trakDur)
	endTimescale = uint64(syncTrak.Mdia.Mdhd.Timescale)
	endTime = uint64(durationMS) * endTimescale / 1000

	stbl := syncTrak.Mdia.Minf.Stbl
	stts := stbl.Stts // TimeToSampleBox
	lastSampleNr, err := stts.GetSampleNrAtTime(endTime)
	if err != nil {
		return 0, 0, err
	}
	stss := stbl.Stss
	if stss != nil {
		foundSyncFrame := false
		for sampleNr := lastSampleNr; sampleNr <= stss.SampleNumber[len(stss.SampleNumber)-1]; sampleNr++ {
			if stss.IsSyncSample(sampleNr) {
				lastSampleNr = sampleNr - 1
				foundSyncFrame = true
				break
			}
		}
		if !foundSyncFrame {
			return 0, 0, fmt.Errorf("did not find any syncframe at or after time")
		}
	}
	lastTime, lastDur := stts.GetDecodeTime(lastSampleNr)
	endTime = lastTime + uint64(lastDur)

	return endTime, endTimescale, nil
}

func cropToTime(inMP4 *mp4.File, endTime, endTimescale uint64, w io.Writer, ifh io.ReadSeeker) error {
	traks := inMP4.Moov.Traks
	tos, err := findTrakEnds(traks, endTime, endTimescale)
	if err != nil {
		return err
	}
	byteRanges := createByteRanges()
	firstOffset, err := fillTrakOutsAndByteRanges(traks, tos, byteRanges)
	if err != nil {
		return err
	}

	err = cropStblChildren(traks, tos)
	if err != nil {
		return err
	}
	updateChunkOffsets(inMP4, firstOffset)

	err = writeUptoMdat(inMP4, endTime, endTimescale, w)
	if err != nil {
		return err
	}

	err = writeMdat(byteRanges, inMP4.Mdat, w, ifh)
	if err != nil {
		return err
	}

	return nil
}

type trakOut struct {
	lastSampleNr  uint32
	endTime       uint64
	lastChunk     mp4.Chunk
	nextInChunkNr uint32
	chunkOffsets  []uint64
}

// findTrakEnds - find where traks end in form of last chunk, lastSampleNr and endTime
func findTrakEnds(traks []*mp4.TrakBox, endTime, endTimescale uint64) (map[uint32]*trakOut, error) {
	tos := make(map[uint32]*trakOut, len(traks))
	for _, trak := range traks {
		trackID := trak.Tkhd.TrackID
		stbl := trak.Mdia.Minf.Stbl
		tos[trackID] = &trakOut{
			nextInChunkNr: 1,
		}
		to := tos[trackID]
		trackTimeScale := trak.Mdia.Mdhd.Timescale
		trackEndTime := endTime
		if trackTimeScale != uint32(endTimescale) {
			trackEndTime = endTime * uint64(trackTimeScale) / endTimescale
		}
		stts := stbl.Stts
		endSampleNr, err := stts.GetSampleNrAtTime(trackEndTime)
		if err != nil {
			return nil, err
		}
		endSampleNr--
		to.lastSampleNr = endSampleNr
		decTime, dur := stts.GetDecodeTime(endSampleNr)
		trackEndTime = decTime + uint64(dur)
		tos[trackID].endTime = trackEndTime
		stsc := stbl.Stsc
		chunkNr, _, err := stsc.ChunkNrFromSampleNr(int(endSampleNr))
		if err != nil {
			return nil, err
		}
		chunk := stsc.GetChunk(uint32(chunkNr))
		to.lastChunk = chunk
	}
	return tos, nil
}

func fillTrakOutsAndByteRanges(traks []*mp4.TrakBox, tos map[uint32]*trakOut, byteRanges *byteRanges) (firstOffset uint64, err error) {
	var currentOutOffset uint64
	var minChunkOffset uint64
	for {
		var trakIDMin uint32
		var stblMin *mp4.StblBox
		minChunkOffset = 1 << 62
		for _, trak := range traks {
			trakID := trak.Tkhd.TrackID
			stbl := trak.Mdia.Minf.Stbl
			to := tos[trakID]
			nextChunkNr := int(to.nextInChunkNr)
			if nextChunkNr > int(to.lastChunk.ChunkNr) {
				continue
			}
			var chunkOffset uint64
			var err error
			if stbl.Stco != nil {
				chunkOffset, err = stbl.Stco.GetOffset(nextChunkNr)
			} else {
				chunkOffset, err = stbl.Co64.GetOffset(nextChunkNr)
			}
			if err != nil {
				return 0, err
			}
			if chunkOffset < minChunkOffset {
				minChunkOffset = chunkOffset
				trakIDMin = trakID
				stblMin = stbl
			}
		}
		if trakIDMin == 0 {
			break //Done
		}
		if firstOffset == 0 {
			firstOffset = minChunkOffset
			currentOutOffset = firstOffset
		}
		to := tos[trakIDMin]
		chunk := stblMin.Stsc.GetChunk(to.nextInChunkNr)
		lastSampleInChunk := chunk.StartSampleNr + chunk.NrSamples - 1
		sampleNrStart := chunk.StartSampleNr
		sampleNrEnd := minUint32(lastSampleInChunk, to.lastSampleNr)
		inOffset := minChunkOffset
		outChunkSize, _ := stblMin.Stsz.GetTotalSampleSize(sampleNrStart, sampleNrEnd)
		byteRanges.addRange(inOffset, inOffset+outChunkSize-1)
		to.chunkOffsets = append(to.chunkOffsets, currentOutOffset)
		currentOutOffset += outChunkSize
		to.nextInChunkNr++
	}
	return firstOffset, nil
}

// updateChunkOffsets - calculate new moov size, and update stco/co64 (chunk offsets)
func updateChunkOffsets(inMP4 *mp4.File, firstOffset uint64) {
	var sizeWithoutMdat uint64 = 0
	for _, box := range inMP4.Children {
		if box.Type() != "mdat" {
			sizeWithoutMdat += box.Size()
		}
	}
	mdatStart := sizeWithoutMdat
	mdatPayloadStart := mdatStart + 8
	deltaOffset := int64(mdatPayloadStart) - int64(firstOffset)
	for _, trak := range inMP4.Moov.Traks {
		stco := trak.Mdia.Minf.Stbl.Stco
		if stco != nil {
			for i := range stco.ChunkOffset {
				stco.ChunkOffset[i] = uint32(int64(stco.ChunkOffset[i]) + deltaOffset)
			}
		} else {
			co64 := trak.Mdia.Minf.Stbl.Co64
			for i := range co64.ChunkOffset {
				co64.ChunkOffset[i] = uint64(int64(co64.ChunkOffset[i]) + deltaOffset)
			}
		}
	}
}

func writeUptoMdat(inMP4 *mp4.File, endTime, endTimescale uint64, w io.Writer) error {
	pos := uint64(0)
	mvhd := inMP4.Moov.Mvhd
	newDur := endTime * uint64(mvhd.Timescale) / endTimescale
	mvhd.Duration = newDur
	for _, trak := range inMP4.Moov.Traks {
		prevDur := trak.Tkhd.Duration
		trak.Tkhd.Duration = newDur
		if newDur > prevDur {
			return fmt.Errorf("new duration %d larger than previous %d", newDur, prevDur)
		}
		durDiff := prevDur - newDur
		if trak.Edts != nil {
			for i := range trak.Edts.Elst {
				for j := range trak.Edts.Elst[i].Entries {
					prevDur := trak.Edts.Elst[i].Entries[j].SegmentDuration
					if prevDur > durDiff {
						trak.Edts.Elst[i].Entries[j].SegmentDuration -= durDiff
					}
				}
			}
		}
	}
	for _, box := range inMP4.Children {
		if box.Type() != "mdat" {
			pos += box.Size()
			err := box.Encode(w)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func writeMdat(byteRanges *byteRanges, mdatIn *mp4.MdatBox, w io.Writer, ifh io.ReadSeeker) error {
	// write mdat header
	mdatPayloadSize := byteRanges.size()
	if mdatPayloadSize+8 >= 1<<32 {
		return fmt.Errorf("too big mdat size for 32 bits: %d", mdatPayloadSize)
	}
	err := mp4.EncodeHeaderWithSize("mdat", mdatPayloadSize+8, false, w)
	if err != nil {
		return err
	}
	// write mdat body
	nrBytesWritten := int64(0)
	for _, br := range byteRanges.ranges {
		n, err := mdatIn.CopyData(int64(br.start), int64(br.end-br.start+1), ifh, w)
		if err != nil {
			return err
		}
		nrBytesWritten += n
	}
	if nrBytesWritten != int64(mdatPayloadSize) {
		return fmt.Errorf("wrote %d instead of %d in mdat", nrBytesWritten, mdatPayloadSize)
	}
	return nil
}

func minUint32(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}

func cropStblChildren(traks []*mp4.TrakBox, trakOuts map[uint32]*trakOut) (err error) {
	for _, trak := range traks {
		trakID := trak.Tkhd.TrackID
		stbl := trak.Mdia.Minf.Stbl
		to := trakOuts[trakID]
		for _, ch := range stbl.Children {
			switch ch.Type() {
			case "stts":
				cropStts(ch.(*mp4.SttsBox), to.lastSampleNr)
			case "stss":
				cropStss(ch.(*mp4.StssBox), to.lastSampleNr)
			case "ctts":
				cropCtts(ch.(*mp4.CttsBox), to.lastSampleNr)
			case "stsc":
				err = cropStsc(ch.(*mp4.StscBox), to.lastSampleNr)
			case "stsz":
				cropStsz(ch.(*mp4.StszBox), to.lastSampleNr)
			case "sdtp":
				cropSdtp(ch.(*mp4.SdtpBox), to.lastSampleNr)
			case "stco":
				updateStco(ch.(*mp4.StcoBox), to.chunkOffsets)
			case "co64":
				updateCo64(ch.(*mp4.Co64Box), to.chunkOffsets)
			}
		}
	}
	return err
}

func cropStts(b *mp4.SttsBox, lastSampleNr uint32) {
	var countedSamples uint32 = 0
	lastEntry := -1
	for i := 0; i < len(b.SampleCount); i++ {
		if countedSamples < lastSampleNr {
			lastEntry++
		}
		if countedSamples+b.SampleCount[i] >= lastSampleNr {
			break
		}
		countedSamples += b.SampleCount[i]
	}
	remaining := lastSampleNr - countedSamples
	if remaining > 0 {
		b.SampleCount[lastEntry] = remaining
	}

	b.SampleCount = b.SampleCount[:lastEntry+1]
	b.SampleTimeDelta = b.SampleTimeDelta[:lastEntry+1]
}

func cropStss(b *mp4.StssBox, lastSampleNr uint32) {
	nrEntries := b.EntryCount()
	nrEntriesToKeep := 0
	for i := uint32(0); i < nrEntries; i++ {
		if b.SampleNumber[i] > lastSampleNr {
			break
		}
		nrEntriesToKeep++
	}
	b.SampleNumber = b.SampleNumber[:nrEntriesToKeep]
}

func cropCtts(b *mp4.CttsBox, lastSampleNr uint32) {
	lastIdx := sort.Search(len(b.EndSampleNr), func(i int) bool { return b.EndSampleNr[i] >= lastSampleNr })
	// Finally cut down the endSampleNr for this index
	b.EndSampleNr[lastIdx] = lastSampleNr
	b.EndSampleNr = b.EndSampleNr[:lastIdx+1]
	b.SampleOffset = b.SampleOffset[:lastIdx]
}

func cropStsc(b *mp4.StscBox, lastSampleNr uint32) error {
	entryIdx := b.FindEntryNrForSampleNr(lastSampleNr, 0)
	lastEntry := b.Entries[entryIdx]
	b.Entries = b.Entries[:entryIdx+1]
	if len(b.SampleDescriptionID) > 0 {
		b.Entries = b.Entries[:entryIdx+1]
	}
	samplesLeft := lastSampleNr - lastEntry.FirstSampleNr + 1
	nrChunksInLast := samplesLeft / lastEntry.SamplesPerChunk
	nrLeft := samplesLeft - nrChunksInLast*lastEntry.SamplesPerChunk
	if nrLeft > 0 {
		sdid := b.GetSampleDescriptionID(int(lastEntry.FirstChunk))
		err := b.AddEntry(lastEntry.FirstChunk+nrChunksInLast, nrLeft, sdid)
		if err != nil {
			return fmt.Errorf("stsc AddEntry: %w", err)
		}
	}
	return nil
}

func cropStsz(b *mp4.StszBox, lastSampleNr uint32) {
	if b.SampleUniformSize == 0 {
		b.SampleSize = b.SampleSize[:lastSampleNr]
	}
	b.SampleNumber = lastSampleNr
}

func cropSdtp(b *mp4.SdtpBox, lastSampleNr uint32) {
	if len(b.Entries) > int(lastSampleNr) {
		b.Entries = b.Entries[:lastSampleNr]
	}
}

func updateStco(b *mp4.StcoBox, offsets []uint64) {
	b.ChunkOffset = make([]uint32, len(offsets))
	for i := range offsets {
		b.ChunkOffset[i] = uint32(offsets[i])
	}
}

func updateCo64(b *mp4.Co64Box, offsets []uint64) {
	b.ChunkOffset = make([]uint64, len(offsets))
	_ = copy(b.ChunkOffset, offsets)
}

type byteRange struct {
	start uint64
	end   uint64 // Included
}

type byteRanges struct {
	ranges []byteRange
}

func createByteRanges() *byteRanges {
	return &byteRanges{}
}

func (b *byteRanges) addRange(start, end uint64) {
	if len(b.ranges) == 0 || b.ranges[len(b.ranges)-1].end+1 != start {
		b.ranges = append(b.ranges, byteRange{start, end})
		return
	}
	b.ranges[len(b.ranges)-1].end = end
}

func (b *byteRanges) size() uint64 {
	var totSize uint64 = 0
	for _, br := range b.ranges {
		totSize += br.end - br.start + 1
	}
	return uint64(totSize)
}
