package mp4

import (
	"fmt"

	"github.com/Eyevinn/mp4ff/bits"
)

var decodersSR map[string]BoxDecoderSR

func init() {
	decodersSR = map[string]BoxDecoderSR{
		"\xa9ART": DecodeGenericContainerBoxSR,
		"\xa9cpy": DecodeGenericContainerBoxSR,
		"\xa9nam": DecodeGenericContainerBoxSR,
		"\xa9too": DecodeGenericContainerBoxSR,
		"ac-3":    DecodeAudioSampleEntrySR,
		"alou":    DecodeLoudnessBaseBoxSR,
		"av01":    DecodeVisualSampleEntrySR,
		"av1C":    DecodeAv1CSR,
		"avc1":    DecodeVisualSampleEntrySR,
		"avc3":    DecodeVisualSampleEntrySR,
		"avcC":    DecodeAvcCSR,
		"btrt":    DecodeBtrtSR,
		"cdat":    DecodeCdatSR,
		"cdsc":    DecodeTrefTypeSR,
		"clap":    DecodeClapSR,
		"co64":    DecodeCo64SR,
		"CoLL":    DecodeCoLLSR,
		"colr":    DecodeColrSR,
		"cslg":    DecodeCslgSR,
		"ctim":    DecodeCtimSR,
		"ctts":    DecodeCttsSR,
		"dac3":    DecodeDac3SR,
		"data":    DecodeDataSR,
		"dec3":    DecodeDec3SR,
		"desc":    DecodeGenericContainerBoxSR,
		"dinf":    DecodeDinfSR,
		"dpnd":    DecodeTrefTypeSR,
		"dref":    DecodeDrefSR,
		"ec-3":    DecodeAudioSampleEntrySR,
		"edts":    DecodeEdtsSR,
		"elng":    DecodeElngSR,
		"elst":    DecodeElstSR,
		"emeb":    DecodeEmebSR,
		"emib":    DecodeEmibSR,
		"emsg":    DecodeEmsgSR,
		"enca":    DecodeAudioSampleEntrySR,
		"encv":    DecodeVisualSampleEntrySR,
		"esds":    DecodeEsdsSR,
		"evte":    DecodeEvteSR,
		"font":    DecodeTrefTypeSR,
		"free":    DecodeFreeSR,
		"frma":    DecodeFrmaSR,
		"ftyp":    DecodeFtypSR,
		"hdlr":    DecodeHdlrSR,
		"hev1":    DecodeVisualSampleEntrySR,
		"hind":    DecodeTrefTypeSR,
		"hint":    DecodeTrefTypeSR,
		"hvc1":    DecodeVisualSampleEntrySR,
		"hvcC":    DecodeHvcCSR,
		"iden":    DecodeIdenSR,
		"ilst":    DecodeIlstSR,
		"iods":    DecodeUnknownSR,
		"ipir":    DecodeTrefTypeSR,
		"kind":    DecodeKindSR,
		"leva":    DecodeLevaSR,
		"ludt":    DecodeLudtSR,
		"mdat":    DecodeMdatSR,
		"mehd":    DecodeMehdSR,
		"mdhd":    DecodeMdhdSR,
		"mdia":    DecodeMdiaSR,
		"meta":    DecodeMetaSR,
		"mfhd":    DecodeMfhdSR,
		"mfra":    DecodeMfraSR,
		"mfro":    DecodeMfroSR,
		"mime":    DecodeMimeSR,
		"minf":    DecodeMinfSR,
		"moof":    DecodeMoofSR,
		"moov":    DecodeMoovSR,
		"mp4a":    DecodeAudioSampleEntrySR,
		"mpod":    DecodeTrefTypeSR,
		"mvex":    DecodeMvexSR,
		"mvhd":    DecodeMvhdSR,
		"nmhd":    DecodeNmhdSR,
		"pasp":    DecodePaspSR,
		"payl":    DecodePaylSR,
		"prft":    DecodePrftSR,
		"pssh":    DecodePsshSR,
		"saio":    DecodeSaioSR,
		"saiz":    DecodeSaizSR,
		"sbgp":    DecodeSbgpSR,
		"schi":    DecodeSchiSR,
		"schm":    DecodeSchmSR,
		"sdtp":    DecodeSdtpSR,
		"senc":    DecodeSencSR,
		"sgpd":    DecodeSgpdSR,
		"sidx":    DecodeSidxSR,
		"silb":    DecodeSilbSR,
		"sinf":    DecodeSinfSR,
		"skip":    DecodeFreeSR,
		"SmDm":    DecodeSmDmSR,
		"smhd":    DecodeSmhdSR,
		"ssix":    DecodeSsixSR,
		"stbl":    DecodeStblSR,
		"stco":    DecodeStcoSR,
		"sthd":    DecodeSthdSR,
		"stpp":    DecodeStppSR,
		"stsc":    DecodeStscSR,
		"stsd":    DecodeStsdSR,
		"stss":    DecodeStssSR,
		"stsz":    DecodeStszSR,
		"sttg":    DecodeSttgSR,
		"stts":    DecodeSttsSR,
		"styp":    DecodeStypSR,
		"subs":    DecodeSubsSR,
		"subt":    DecodeTrefTypeSR,
		"sync":    DecodeTrefTypeSR,
		"tenc":    DecodeTencSR,
		"tfdt":    DecodeTfdtSR,
		"tfhd":    DecodeTfhdSR,
		"tfra":    DecodeTfraSR,
		"tkhd":    DecodeTkhdSR,
		"tlou":    DecodeLoudnessBaseBoxSR,
		"traf":    DecodeTrafSR,
		"trak":    DecodeTrakSR,
		"tref":    DecodeTrefSR,
		"trep":    DecodeTrepSR,
		"trex":    DecodeTrexSR,
		"trun":    DecodeTrunSR,
		"udta":    DecodeUdtaSR,
		"url ":    DecodeURLBoxSR,
		"uuid":    DecodeUUIDBoxSR,
		"vdep":    DecodeTrefTypeSR,
		"vlab":    DecodeVlabSR,
		"vmhd":    DecodeVmhdSR,
		"vp08":    DecodeVisualSampleEntrySR,
		"vp09":    DecodeVisualSampleEntrySR,
		"vpcC":    DecodeVppCSR,
		"vplx":    DecodeTrefTypeSR,
		"vsid":    DecodeVsidSR,
		"vtta":    DecodeVttaSR,
		"vttc":    DecodeVttcSR,
		"vttC":    DecodeVttCSR,
		"vtte":    DecodeVtteSR,
		"wvtt":    DecodeWvttSR,
	}
}

// BoxDecoderSR is function signature of the Box DecodeSR method
type BoxDecoderSR func(hdr BoxHeader, startPos uint64, sw bits.SliceReader) (Box, error)

// DecodeBoxSR - decode a box from SliceReader
func DecodeBoxSR(startPos uint64, sr bits.SliceReader) (Box, error) {
	var err error
	var b Box

	h, err := DecodeHeaderSR(sr)
	if err != nil {
		return nil, err
	}

	maxSize := uint64(sr.NrRemainingBytes()) + uint64(h.Hdrlen)
	// In the following, we do not block mdat to allow for the case
	// that the first kiloBytes of a file are fetched and parsed to
	// get the init part of a file. In the future, a new decode option that
	// stops before the mdat starts is a better alternative.
	if h.Size > maxSize && h.Name != "mdat" {
		return nil, fmt.Errorf("decode box %q, size %d too big (max %d)", h.Name, h.Size, maxSize)
	}

	d, ok := decodersSR[h.Name]

	if !ok {
		b, err = DecodeUnknownSR(h, startPos, sr)
	} else {
		b, err = d(h, startPos, sr)
	}
	if err != nil {
		return nil, fmt.Errorf("decode %s pos %d: %w", h.Name, startPos, err)
	}

	return b, nil
}

// DecodeHeaderSR - decode a box header (size + box type + possible largeSize) from sr
func DecodeHeaderSR(sr bits.SliceReader) (BoxHeader, error) {
	size := uint64(sr.ReadUint32())
	boxType := sr.ReadFixedLengthString(4)
	headerLen := boxHeaderSize
	switch size {
	case 1: // size 1 means large size in next 8 bytes
		size = sr.ReadUint64()
		headerLen += largeSizeLen
	case 0: // size 0 means to end of file
		return BoxHeader{}, fmt.Errorf("Size 0, meaning to end of file, not supported")
	}
	if uint64(headerLen) > size {
		return BoxHeader{}, fmt.Errorf("box header size %d exceeds box size %d", headerLen, size)
	}
	return BoxHeader{boxType, size, headerLen}, sr.AccError()
}

// DecodeFile - parse and decode a file from reader r with optional file options.
// For example, the file options overwrite the default decode or encode mode.
func DecodeFileSR(sr bits.SliceReader, options ...Option) (*File, error) {
	f := NewFile()

	// apply options to change the default decode or encode mode
	f.ApplyOptions(options...)

	var boxStartPos uint64 = 0
	lastBoxType := ""

	if f.fileDecMode == DecModeLazyMdat {
		return nil, fmt.Errorf("no support for lazy mdat in DecodeFileSR")
	}

LoopBoxes:
	for {
		var box Box
		var err error
		if sr.NrRemainingBytes() == 0 {
			break LoopBoxes
		}

		box, err = DecodeBoxSR(boxStartPos, sr)
		if err != nil {
			return nil, err
		}
		boxType, boxSize := box.Type(), box.Size()
		switch boxType {
		case "mdat":
			if f.isFragmented {
				if lastBoxType != "moof" {
					return nil, fmt.Errorf("does not support %v between moof and mdat", lastBoxType)
				}
			} else {
				if f.Mdat != nil {
					oldPayloadSize := f.Mdat.Size() - f.Mdat.HeaderSize()
					newMdat := box.(*MdatBox)
					newPayloadSize := newMdat.Size() - newMdat.HeaderSize()
					if oldPayloadSize > 0 && newPayloadSize > 0 {
						return nil, fmt.Errorf("only one non-empty mdat box supported (payload sizes %d and %d)",
							oldPayloadSize, newPayloadSize)
					}
				}
			}
		case "moof":
			moof := box.(*MoofBox)
			for _, traf := range moof.Trafs {
				if ok, parsed := traf.ContainsSencBox(); ok && !parsed {
					isEncrypted := true
					defaultIVSize := byte(0) // Should get this from tenc in sinf
					if f.Moov != nil {
						trackID := traf.Tfhd.TrackID
						isEncrypted = f.Moov.IsEncrypted(trackID)
						sinf := f.Moov.GetSinf(trackID)
						if sinf != nil && sinf.Schi != nil && sinf.Schi.Tenc != nil {
							defaultIVSize = sinf.Schi.Tenc.DefaultPerSampleIVSize
						}
					}
					if isEncrypted {
						err = traf.ParseReadSenc(defaultIVSize, moof.StartPos)
						if err != nil {
							return nil, err
						}
					}
				}
			}
		}
		f.AddChild(box, boxStartPos)
		lastBoxType = boxType
		boxStartPos += boxSize
	}
	return f, nil
}
