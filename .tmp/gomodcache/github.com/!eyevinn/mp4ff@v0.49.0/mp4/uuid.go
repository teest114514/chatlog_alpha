package mp4

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/Eyevinn/mp4ff/bits"
)

// UUID - 16-byte KeyID or SystemID
type UUID []byte

func (u UUID) String() string {
	if len(u) != 16 {
		return fmt.Sprintf("bad uuid %q", hex.EncodeToString(u))
	}
	h := hex.EncodeToString(u[:])
	return fmt.Sprintf("%s-%s-%s-%s-%s", h[0:8], h[8:12], h[12:16], h[16:20], h[20:32])
}

// Equal compares with other UUID
func (u UUID) Equal(a UUID) bool {
	return bytes.Equal(u, a)
}

// NewUUIDFromString creates a UUID from a hexadecimal, uuid-string or base64 string
func NewUUIDFromString(h string) (UUID, error) {
	return createUUID(h)
}

const (
	// The following UUIDs belong to Microsoft Smooth Streaming Protocol (MSS)

	// UUIDMssSm - MSS StreamManifest UUID [MS-SSTR 2.2.7.2]
	UUIDMssSm = "3c2fe51b-efee-40a3-ae815300199dc348"

	// UUIDMssLs - MSS LiveServerManifest UUID [MS-SSTR 2.2.7.3]
	UUIDMssLsm = "a5d40b30-e814-11dd-ba2f-0800200c9a66"

	// UUIDTfxd - MSS tfxd UUID [MS-SSTR 2.2.4.4]
	UUIDTfxd = "6d1d9b05-42d5-44e6-80e2-141daff757b2"

	// UUIDTfrf - MSS tfrf UUID [MS-SSTR 2.2.4.5]
	UUIDTfrf = "d4807ef2-ca39-4695-8e54-26cb9e46a79f"

	// UUIDPiffSenc - PIFF UUID for Sample Encryption Box (PIFF 1.1 spec)
	UUIDPiffSenc = "a2394f52-5a9b-4f14-a244-6c427c648df4"
)

// NewTrfrfBox creates a new TfrfBox with values.
// fragmentCount is the number of fragments, andb both
// fragmentAbsoluteTimes and fragmentAbsoluteDurations must be slices of that length.
func NewTfrfBox(fragmentCount byte, fragmentAbsoluteTimes, fragmentAbsoluteDurations []uint64) *UUIDBox {
	return &UUIDBox{
		uuid: mustCreateUUID(UUIDTfrf),
		Tfrf: &TfrfData{
			Version:                   0,
			Flags:                     0,
			FragmentCount:             fragmentCount,
			FragmentAbsoluteTimes:     fragmentAbsoluteTimes,
			FragmentAbsoluteDurations: fragmentAbsoluteDurations,
		},
	}
}

// NewTfxdBox creates a new TfxdBox with values.
func NewTfxdBox(fragmentAbsoluteTime, fragmentAbsoluteDuration uint64) *UUIDBox {
	return &UUIDBox{
		uuid: mustCreateUUID(UUIDTfxd),
		Tfxd: &TfxdData{
			FragmentAbsoluteTime:     fragmentAbsoluteTime,
			FragmentAbsoluteDuration: fragmentAbsoluteDuration,
		},
	}
}

// createUUID - create uuid from hex, uuid-formatted hex, or base64 string
func createUUID(u string) (UUID, error) {
	b, err := UnpackKey(u)
	if err != nil {
		return nil, err
	}
	return UUID(b), nil
}

// mustCreateUUID - create uuid from string. Panic for bad string
func mustCreateUUID(u string) UUID {
	b, err := createUUID(u)
	if err != nil {
		panic(err.Error())
	}
	return b
}

var (
	uuidTfxd     UUID = mustCreateUUID(UUIDTfxd)
	uuidTfrf     UUID = mustCreateUUID(UUIDTfrf)
	uuidPiffSenc UUID = mustCreateUUID(UUIDPiffSenc)
)

// UUIDBox - Used as container for MSS boxes tfxd and tfrf
// For unknown UUID, the data after the UUID is stored as UnknownPayload
type UUIDBox struct {
	uuid           UUID
	Tfxd           *TfxdData
	Tfrf           *TfrfData
	Senc           *SencBox
	StartPos       uint64
	UnknownPayload []byte
}

// UUID - Return UUID as formatted string
func (u *UUIDBox) UUID() string {
	return u.uuid.String()
}

// UUID - Set UUID from string corresponding to 16 bytes.
// The input should be a UUID-formatted hex string, plain hex or baset64 encoded.
func (u *UUIDBox) SetUUID(uuid string) (err error) {
	u.uuid, err = createUUID(uuid)
	return err
}

// TfxdData - MSS TfxdBox data after UUID part
// Defined in MSS-SSTR v20180912 section 2.2.4.4
type TfxdData struct {
	Version                  byte
	Flags                    uint32
	FragmentAbsoluteTime     uint64
	FragmentAbsoluteDuration uint64
}

// TfrfData - MSS TfrfBox data after UUID part
// Defined in MSS-SSTR v20180912 section 2.2.4.5
type TfrfData struct {
	Version                   byte
	Flags                     uint32
	FragmentCount             byte
	FragmentAbsoluteTimes     []uint64
	FragmentAbsoluteDurations []uint64
}

// DecodeUUIDBox - decode a UUID box including tfxd or tfrf
func DecodeUUIDBox(hdr BoxHeader, startPos uint64, r io.Reader) (Box, error) {
	data, err := readBoxBody(r, hdr)
	if err != nil {
		return nil, err
	}
	sr := bits.NewFixedSliceReader(data)
	return DecodeUUIDBoxSR(hdr, startPos, sr)
}

// DecodeUUIDBoxSR - decode a UUID box including tfxd or tfrf
func DecodeUUIDBoxSR(hdr BoxHeader, startPos uint64, sr bits.SliceReader) (Box, error) {
	b := &UUIDBox{
		StartPos: startPos,
		uuid:     sr.ReadBytes(16),
	}
	switch b.UUID() {
	case UUIDTfxd:
		tfxd, err := decodeTfxd(sr)
		if err != nil {
			return nil, err
		}
		b.Tfxd = tfxd
	case UUIDTfrf:
		tfrf, err := decodeTfrf(sr)
		if err != nil {
			return nil, err
		}
		b.Tfrf = tfrf
	case UUIDPiffSenc:
		if hdr.Size < 16 {
			return nil, fmt.Errorf("uuid box size too small: %d < 16", hdr.Size)
		}
		// This is like a SencBox except that there is no size and type. Offset and sizes must be slightly adjusted.
		subHdr := BoxHeader{"senc", hdr.Size - 16, 8}
		box, err := DecodeSencSR(subHdr, b.StartPos+16, sr)
		if err != nil {
			return nil, fmt.Errorf("failed to decode senc in UUID: %w", err)
		}
		b.Senc = box.(*SencBox)
	default:
		if hdr.Size < 8+16 {
			return nil, fmt.Errorf("uuid box size too small: %d < 24", hdr.Size)
		}
		b.UnknownPayload = sr.ReadBytes(int(hdr.Size) - 8 - 16)
	}

	return b, sr.AccError()
}

// Type - return box type
func (b *UUIDBox) Type() string {
	return "uuid"
}

// Size - return calculated size including tfxd/tfrf
func (b *UUIDBox) Size() uint64 {
	var size uint64 = 8 + 16
	switch u := b.uuid; {
	case u.Equal(uuidTfxd):
		size += b.Tfxd.size()
	case u.Equal(uuidTfrf):
		size += b.Tfrf.size()
	case u.Equal(uuidPiffSenc):
		size += b.Senc.Size() - 8 // -8 because no header
	default:
		size += uint64(len(b.UnknownPayload))
	}
	return size
}

// Encode - write box to w
func (b *UUIDBox) Encode(w io.Writer) error {
	sw := bits.NewFixedSliceWriter(int(b.Size()))
	err := b.EncodeSW(sw)
	if err != nil {
		return err
	}
	_, err = w.Write(sw.Bytes())
	return err
}

// EncodeSW - box-specific encode to slicewriter
func (b *UUIDBox) EncodeSW(sw bits.SliceWriter) error {
	err := EncodeHeaderSW(b, sw)
	if err != nil {
		return err
	}
	sw.WriteBytes(b.uuid[:])
	switch u := b.uuid; {
	case u.Equal(uuidTfxd):
		err = b.Tfxd.encode(sw)
	case u.Equal(uuidTfrf):
		err = b.Tfrf.encode(sw)
	case u.Equal(uuidPiffSenc):
		err = b.Senc.EncodeSWNoHdr(sw)
	default:
		sw.WriteBytes(b.UnknownPayload)
	}
	if err != nil {
		return err
	}
	return sw.AccError()
}

// SubType - interpret the UUID as a known sub type or unknown
func (b *UUIDBox) SubType() string {
	switch u := b.uuid; {
	case u.Equal(uuidTfxd):
		return "tfxd"
	case u.Equal(uuidTfrf):
		return "tfrf"
	case u.Equal(uuidPiffSenc):
		return "senc"
	default:
		return "unknown"
	}
}

func decodeTfxd(s bits.SliceReader) (*TfxdData, error) {
	versionAndFlags := s.ReadUint32()
	version := byte(versionAndFlags >> 24)
	var fragmentAbsoluteTime uint64
	var fragmentAbsoluteDuration uint64
	if version == 0 {
		fragmentAbsoluteTime = uint64(s.ReadUint32())
		fragmentAbsoluteDuration = uint64(s.ReadUint32())
	} else {
		fragmentAbsoluteTime = s.ReadUint64()
		fragmentAbsoluteDuration = s.ReadUint64()
	}

	t := &TfxdData{
		Version:                  version,
		Flags:                    versionAndFlags & flagsMask,
		FragmentAbsoluteTime:     fragmentAbsoluteTime,
		FragmentAbsoluteDuration: fragmentAbsoluteDuration,
	}
	return t, nil
}

func (t *TfxdData) size() uint64 {
	return 4 + 8 + 8*uint64(t.Version)
}

func (t *TfxdData) encode(sw bits.SliceWriter) error {
	versionAndFlags := (uint32(t.Version) << 24) + t.Flags
	sw.WriteUint32(versionAndFlags)
	if t.Version == 0 {
		sw.WriteUint32(uint32(t.FragmentAbsoluteTime))
		sw.WriteUint32(uint32(t.FragmentAbsoluteDuration))
	} else {
		sw.WriteUint64(t.FragmentAbsoluteTime)
		sw.WriteUint64(t.FragmentAbsoluteDuration)
	}
	return sw.AccError()
}

func decodeTfrf(s bits.SliceReader) (*TfrfData, error) {
	versionAndFlags := s.ReadUint32()
	version := byte(versionAndFlags >> 24)
	t := &TfrfData{
		Version:       version,
		Flags:         versionAndFlags & flagsMask,
		FragmentCount: s.ReadUint8(),
	}
	if t.Version == 0 {
		for i := byte(0); i < t.FragmentCount; i++ {
			t.FragmentAbsoluteTimes = append(t.FragmentAbsoluteTimes, uint64(s.ReadUint32()))
			t.FragmentAbsoluteDurations = append(t.FragmentAbsoluteDurations, uint64(s.ReadUint32()))
		}
	} else {
		for i := byte(0); i < t.FragmentCount; i++ {
			t.FragmentAbsoluteTimes = append(t.FragmentAbsoluteTimes, s.ReadUint64())
			t.FragmentAbsoluteDurations = append(t.FragmentAbsoluteDurations, s.ReadUint64())
		}
	}
	return t, nil
}

func (t *TfrfData) size() uint64 {
	return 4 + 1 + (8+8*uint64(t.Version))*uint64(t.FragmentCount)
}

func (t *TfrfData) encode(sw bits.SliceWriter) error {
	versionAndFlags := (uint32(t.Version) << 24) + t.Flags
	sw.WriteUint32(versionAndFlags)
	sw.WriteUint8(t.FragmentCount)
	if t.Version == 0 {
		for i := byte(0); i < t.FragmentCount; i++ {
			sw.WriteUint32(uint32(t.FragmentAbsoluteTimes[i]))
			sw.WriteUint32(uint32(t.FragmentAbsoluteDurations[i]))
		}
	} else {
		for i := byte(0); i < t.FragmentCount; i++ {
			sw.WriteUint64(t.FragmentAbsoluteTimes[i])
			sw.WriteUint64(t.FragmentAbsoluteDurations[i])
		}
	}
	return sw.AccError()
}

// Info - box-specific info
func (b *UUIDBox) Info(w io.Writer, specificBoxLevels, indent, indentStep string) error {
	bd := newInfoDumper(w, indent, b, -1, 0)
	bd.write(" - uuid: %s", b.uuid)
	bd.write(" - subType: %s", b.SubType())
	level := getInfoLevel(b, specificBoxLevels)
	if level > 0 {
		switch b.SubType() {
		case "tfxd":
			bd.write(" - absTime=%d absDur=%d", b.Tfxd.FragmentAbsoluteTime, b.Tfxd.FragmentAbsoluteDuration)
		case "tfrf":
			for i := 0; i < int(b.Tfrf.FragmentCount); i++ {
				bd.write(" - [%d]: absTime=%d absDur=%d", i+1, b.Tfrf.FragmentAbsoluteTimes[i], b.Tfrf.FragmentAbsoluteDurations[i])
			}
		case "senc":
			err := b.Senc.Info(w, specificBoxLevels, indent+"    ", indentStep)
			if err != nil {
				return fmt.Errorf("piff senc: %w", err)
			}
		default:
			bd.write(" - payload: %s", hex.EncodeToString(b.UnknownPayload))
		}
	}
	return bd.err
}

// UnpackKey unpacks a hex or base64 encoded 16-byte key.
// The key can be in uuid formats with hyphens at positions 8, 13, 18, 23.
func UnpackKey(inKey string) (key []byte, err error) {
	shorten := func(s string) string {
		return fmt.Sprintf("%s...%s", s[:6], s[len(s)-6:])
	}
	switch len(inKey) {
	case 36:
		if inKey[8] != '-' || inKey[13] != '-' || inKey[18] != '-' || inKey[23] != '-' {
			return nil, fmt.Errorf("bad uuid format: %s", shorten(inKey))
		}
		inKey = strings.ReplaceAll(inKey, "-", "")
		if len(inKey) != 32 {
			return nil, fmt.Errorf("bad uuid format: %s", shorten(inKey))
		}
		key, err = hex.DecodeString(inKey)
		if err != nil {
			return nil, fmt.Errorf("bad uuid %s: %w", shorten(inKey), err)
		}
	case 32:
		key, err = hex.DecodeString(inKey)
		if err != nil {
			return nil, fmt.Errorf("bad hex %s: %w", shorten(inKey), err)
		}
	case 24:
		key, err = base64.StdEncoding.DecodeString(inKey)
		if err != nil {
			return nil, fmt.Errorf("bad base64 %s: %w", shorten(inKey), err)
		}
	default:
		return nil, fmt.Errorf("cannot decode key %s", inKey)
	}
	return key, nil
}
