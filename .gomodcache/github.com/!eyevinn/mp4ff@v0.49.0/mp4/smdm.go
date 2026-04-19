package mp4

import (
	"fmt"
	"io"

	"github.com/Eyevinn/mp4ff/bits"
)

// SmDmBox - Sample Mastering Display Metadata Box (smdm)
// Can be used for VP9 codec in vp09 box (VisualSampleEntryBox).
// Defined in [WebM Project].
//
// [WebM Project]: https://www.webmproject.org/vp9/mp4/
type SmDmBox struct {
	Version                 byte
	Flags                   uint32
	PrimaryRChromaticityX   uint16
	PrimaryRChromaticityY   uint16
	PrimaryGChromaticityX   uint16
	PrimaryGChromaticityY   uint16
	PrimaryBChromaticityX   uint16
	PrimaryBChromaticityY   uint16
	WhitePointChromaticityX uint16
	WhitePointChromaticityY uint16
	LuminanceMax            uint32
	LuminanceMin            uint32
}

// CreateSmDmBox - Create a new SmDmBox with specified values
func CreateSmDmBox(primaryRX, primaryRY, primaryGX, primaryGY, primaryBX, primaryBY, whitePointX, whitePointY uint16,
	luminanceMax, luminanceMin uint32) *SmDmBox {
	return &SmDmBox{
		Version:                 0,
		Flags:                   0,
		PrimaryRChromaticityX:   primaryRX,
		PrimaryRChromaticityY:   primaryRY,
		PrimaryGChromaticityX:   primaryGX,
		PrimaryGChromaticityY:   primaryGY,
		PrimaryBChromaticityX:   primaryBX,
		PrimaryBChromaticityY:   primaryBY,
		WhitePointChromaticityX: whitePointX,
		WhitePointChromaticityY: whitePointY,
		LuminanceMax:            luminanceMax,
		LuminanceMin:            luminanceMin,
	}
}

const smDmBoxSize = boxHeaderSize + 4 + 8*2 + 2*4 // Header + version/flags + 8 uint16s + 2 uint32s

// DecodeSmDm - box-specific decode
func DecodeSmDm(hdr BoxHeader, startPos uint64, r io.Reader) (Box, error) {
	// Only allow header size of 8 and correct total box size
	if hdr.Hdrlen != boxHeaderSize || hdr.Size != smDmBoxSize {
		return nil, fmt.Errorf("invalid box size %d", hdr.Size)
	}
	data, err := readBoxBody(r, hdr)
	if err != nil {
		return nil, err
	}
	sr := bits.NewFixedSliceReader(data)
	return DecodeSmDmSR(hdr, startPos, sr)
}

// DecodeSmDmSR - decode box from SliceReader
func DecodeSmDmSR(hdr BoxHeader, startPos uint64, sr bits.SliceReader) (Box, error) {
	// Only allow header size of 8 and correct total box size
	if hdr.Hdrlen != boxHeaderSize || hdr.Size != smDmBoxSize {
		return nil, fmt.Errorf("invalid box size %d", hdr.Size)
	}
	b := &SmDmBox{}
	b.Version = sr.ReadUint8()
	b.Flags = sr.ReadUint24()
	b.PrimaryRChromaticityX = sr.ReadUint16()
	b.PrimaryRChromaticityY = sr.ReadUint16()
	b.PrimaryGChromaticityX = sr.ReadUint16()
	b.PrimaryGChromaticityY = sr.ReadUint16()
	b.PrimaryBChromaticityX = sr.ReadUint16()
	b.PrimaryBChromaticityY = sr.ReadUint16()
	b.WhitePointChromaticityX = sr.ReadUint16()
	b.WhitePointChromaticityY = sr.ReadUint16()
	b.LuminanceMax = sr.ReadUint32()
	b.LuminanceMin = sr.ReadUint32()
	return b, sr.AccError()
}

// Type - box type
func (b *SmDmBox) Type() string {
	return "SmDm"
}

// Size - calculated size of box
func (b *SmDmBox) Size() uint64 {
	return smDmBoxSize
}

// Encode - write box to w
func (b *SmDmBox) Encode(w io.Writer) error {
	sw := bits.NewFixedSliceWriter(int(b.Size()))
	err := b.EncodeSW(sw)
	if err != nil {
		return err
	}
	_, err = w.Write(sw.Bytes())
	return err
}

// EncodeSW - box-specific encode to slicewriter
func (b *SmDmBox) EncodeSW(sw bits.SliceWriter) error {
	err := EncodeHeaderSW(b, sw)
	if err != nil {
		return err
	}
	sw.WriteUint8(b.Version)
	sw.WriteUint24(b.Flags)
	sw.WriteUint16(b.PrimaryRChromaticityX)
	sw.WriteUint16(b.PrimaryRChromaticityY)
	sw.WriteUint16(b.PrimaryGChromaticityX)
	sw.WriteUint16(b.PrimaryGChromaticityY)
	sw.WriteUint16(b.PrimaryBChromaticityX)
	sw.WriteUint16(b.PrimaryBChromaticityY)
	sw.WriteUint16(b.WhitePointChromaticityX)
	sw.WriteUint16(b.WhitePointChromaticityY)
	sw.WriteUint32(b.LuminanceMax)
	sw.WriteUint32(b.LuminanceMin)
	return sw.AccError()
}

// Info - write box-specific information
func (b *SmDmBox) Info(w io.Writer, specificBoxLevels, indent, indentStep string) error {
	bd := newInfoDumper(w, indent, b, -1, 0)
	bd.write(" - primaryR: (%d,%d)", b.PrimaryRChromaticityX, b.PrimaryRChromaticityY)
	bd.write(" - primaryG: (%d,%d)", b.PrimaryGChromaticityX, b.PrimaryGChromaticityY)
	bd.write(" - primaryB: (%d,%d)", b.PrimaryBChromaticityX, b.PrimaryBChromaticityY)
	bd.write(" - whitePoint: (%d,%d)", b.WhitePointChromaticityX, b.WhitePointChromaticityY)
	bd.write(" - luminanceMax: %d", b.LuminanceMax)
	bd.write(" - luminanceMin: %d", b.LuminanceMin)
	return bd.err
}
