package mp4

import (
	"fmt"
	"io"

	"github.com/Eyevinn/mp4ff/bits"
)

// CoLLBox - Content Light Level Box (coll)
// Can be used for VP9 codec in vp09 box (VisualSampleEntryBox).
// Defined in [WebM Project].
//
// [WebM Project]: https://www.webmproject.org/vp9/mp4/
type CoLLBox struct {
	Version byte
	Flags   uint32
	MaxCLL  uint16 // Maximum Content Light Level
	MaxFALL uint16 // Maximum Frame-Average Light Level
}

// CreateCoLLBox - Create a new CoLLBox with specified values
func CreateCoLLBox(maxCLL, maxFALL uint16) *CoLLBox {
	return &CoLLBox{
		Version: 0,
		Flags:   0,
		MaxCLL:  maxCLL,
		MaxFALL: maxFALL,
	}
}

const coLLBoxSize = boxHeaderSize + 4 + 2*2 // Header + version/flags + 2 uint16s

// DecodeCoLL - box-specific decode
func DecodeCoLL(hdr BoxHeader, startPos uint64, r io.Reader) (Box, error) {
	// Only allow header size of 8 and correct total box size
	if hdr.Hdrlen != boxHeaderSize || hdr.Size != coLLBoxSize {
		return nil, fmt.Errorf("invalid box size %d", hdr.Size)
	}
	data, err := readBoxBody(r, hdr)
	if err != nil {
		return nil, err
	}
	sr := bits.NewFixedSliceReader(data)
	return DecodeCoLLSR(hdr, startPos, sr)
}

// DecodeCoLLSR - decode box from SliceReader
func DecodeCoLLSR(hdr BoxHeader, startPos uint64, sr bits.SliceReader) (Box, error) {
	// Only allow header size of 8 and correct total box size
	if hdr.Hdrlen != boxHeaderSize || hdr.Size != coLLBoxSize {
		return nil, fmt.Errorf("invalid box size %d", hdr.Size)
	}
	b := &CoLLBox{}
	b.Version = sr.ReadUint8()
	b.Flags = sr.ReadUint24()
	b.MaxCLL = sr.ReadUint16()
	b.MaxFALL = sr.ReadUint16()
	return b, sr.AccError()
}

// Type - box type
func (b *CoLLBox) Type() string {
	return "CoLL"
}

// Size - calculated size of box
func (b *CoLLBox) Size() uint64 {
	return coLLBoxSize
}

// Encode - write box to w
func (b *CoLLBox) Encode(w io.Writer) error {
	sw := bits.NewFixedSliceWriter(int(b.Size()))
	err := b.EncodeSW(sw)
	if err != nil {
		return err
	}
	_, err = w.Write(sw.Bytes())
	return err
}

// EncodeSW - box-specific encode to slicewriter
func (b *CoLLBox) EncodeSW(sw bits.SliceWriter) error {
	err := EncodeHeaderSW(b, sw)
	if err != nil {
		return err
	}
	sw.WriteUint8(b.Version)
	sw.WriteUint24(b.Flags)
	sw.WriteUint16(b.MaxCLL)
	sw.WriteUint16(b.MaxFALL)
	return sw.AccError()
}

// Info - write box-specific information
func (b *CoLLBox) Info(w io.Writer, specificBoxLevels, indent, indentStep string) error {
	bd := newInfoDumper(w, indent, b, -1, 0)
	bd.write(" - maxCLL: %d", b.MaxCLL)
	bd.write(" - maxFALL: %d", b.MaxFALL)
	return bd.err
}
