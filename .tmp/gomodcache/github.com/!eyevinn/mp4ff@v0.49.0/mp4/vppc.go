package mp4

import (
	"fmt"
	"io"

	"github.com/Eyevinn/mp4ff/bits"
)

// VppCBox - VP Codec Configuration Box (vpcC)
// The VPCodecConfigurationBox contains decoder configuration information
// formatted according to the VP codec configuration syntax.
//
// [WebM VP Codec Configuration]: https://www.webmproject.org/vp9/mp4/
type VppCBox struct {
	Version                 byte
	Flags                   uint32
	Profile                 byte
	Level                   byte
	BitDepth                byte
	ChromaSubsampling       byte
	VideoFullRangeFlag      byte
	ColourPrimaries         byte
	TransferCharacteristics byte
	MatrixCoefficients      byte
	CodecInitData           []byte
}

// DecodeVppC - box-specific decode
func DecodeVppC(hdr BoxHeader, startPos uint64, r io.Reader) (Box, error) {
	if hdr.Size < 20 {
		return nil, fmt.Errorf("box too short < 20 bytes")
	}
	data, err := readBoxBody(r, hdr)
	if err != nil {
		return nil, err
	}
	sr := bits.NewFixedSliceReader(data)
	return DecodeVppCSR(hdr, startPos, sr)
}

// DecodeVppCSR - box-specific decode
func DecodeVppCSR(hdr BoxHeader, startPos uint64, sr bits.SliceReader) (Box, error) {
	if hdr.Size < 20 {
		return nil, fmt.Errorf("box too short < 20 bytes")
	}
	b := VppCBox{}
	versionAndFlags := sr.ReadUint32()
	b.Version = byte(versionAndFlags >> 24)
	b.Flags = versionAndFlags & flagsMask

	if b.Version != 1 {
		return nil, fmt.Errorf("version %d not supported", b.Version)
	}

	b.Profile = sr.ReadUint8()
	b.Level = sr.ReadUint8()

	// Read bit depth and chroma subsampling packed in one byte
	packedByte := sr.ReadUint8()
	b.BitDepth = (packedByte >> 4) & 0x0F          // top 4 bits
	b.ChromaSubsampling = (packedByte >> 1) & 0x07 // next 3 bits
	b.VideoFullRangeFlag = packedByte & 0x01       // last bit

	b.ColourPrimaries = sr.ReadUint8()
	b.TransferCharacteristics = sr.ReadUint8()
	b.MatrixCoefficients = sr.ReadUint8()

	codecInitSize := sr.ReadUint16()
	if hdr.Size != b.expectedSize(codecInitSize) {
		return nil, fmt.Errorf("incorrect box size")
	}
	if codecInitSize != 0 {
		b.CodecInitData = sr.ReadBytes(int(codecInitSize))
	}
	return &b, sr.AccError()
}

// Type - box type
func (b *VppCBox) Type() string {
	return "vpcC"
}

// Size - calculated size of box
func (b *VppCBox) Size() uint64 {
	return uint64(boxHeaderSize + 4 + 6 + 2 + len(b.CodecInitData))
}

func (b *VppCBox) expectedSize(codecInitSize uint16) uint64 {
	return uint64(boxHeaderSize+4+6+2) + uint64(codecInitSize)
}

// Encode - write box to w
func (b *VppCBox) Encode(w io.Writer) error {
	sw := bits.NewFixedSliceWriter(int(b.Size()))
	err := b.EncodeSW(sw)
	if err != nil {
		return err
	}
	_, err = w.Write(sw.Bytes())
	return err
}

// EncodeSW - box-specific encode to slicewriter
func (b *VppCBox) EncodeSW(sw bits.SliceWriter) error {
	err := EncodeHeaderSW(b, sw)
	if err != nil {
		return err
	}
	versionAndFlags := (uint32(b.Version) << 24) + b.Flags
	sw.WriteUint32(versionAndFlags)
	sw.WriteUint8(b.Profile)
	sw.WriteUint8(b.Level)

	// Pack bit depth, chroma subsampling and video full range flag into one byte
	packedByte := (b.BitDepth << 4) | (b.ChromaSubsampling << 1) | b.VideoFullRangeFlag
	sw.WriteUint8(packedByte)

	sw.WriteUint8(b.ColourPrimaries)
	sw.WriteUint8(b.TransferCharacteristics)
	sw.WriteUint8(b.MatrixCoefficients)

	sw.WriteUint16(uint16(len(b.CodecInitData)))
	sw.WriteBytes(b.CodecInitData)

	return sw.AccError()
}

// Info - write box info to w
func (b *VppCBox) Info(w io.Writer, specificBoxLevels, indent, indentStep string) error {
	bd := newInfoDumper(w, indent, b, -1, 0)
	bd.write(" - profile: %d", b.Profile)
	bd.write(" - level: %d", b.Level)
	bd.write(" - bitDepth: %d", b.BitDepth)
	bd.write(" - chromaSubsampling: %d", b.ChromaSubsampling)
	bd.write(" - videoFullRangeFlag: %d", b.VideoFullRangeFlag)
	bd.write(" - colourPrimaries: %d", b.ColourPrimaries)
	bd.write(" - transferCharacteristics: %d", b.TransferCharacteristics)
	bd.write(" - matrixCoefficients: %d", b.MatrixCoefficients)
	bd.write(" - codecInitSize: %d", len(b.CodecInitData))
	return bd.err
}
