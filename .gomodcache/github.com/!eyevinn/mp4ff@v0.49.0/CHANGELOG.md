# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)

## [Unreleased]

- Nothing yet

## [0.49.0] - 2025-06-26

### Added

- NewPsshBox function

### Changed

* `mp4.DecodeFile` can return a partially decoded file with an error
* `mp4ff-info` may print a partially parsed box tree together with an error

### Fixed

- Handle multi-segment files with sidx without styp #430
- Improved RemoveEncryptionBoxes function

## [0.48.0] - 2025-03-28

### Changed

- mp4.NewUUIDFromHex() changed to more general mp4.NewUUIDFromString()
- cmd/mp4ff-decrypt -key option instead of -k. Takes hex or base64 value
- cmd/mp4ff-encrypt -key and -kid options now take hex or base64 values
- Replaced mp4.AlouBox and mp4.TlouBox with a common mp4.LoudnessBaseBox
- mp4.Measurement changed to clearer mp4.LoudnessMeasurement

### Added

- mp4.SetUUID() can take base64 string as well as hex-encoded.
- Support for weird dac3 box with initial 4 zero bytes (#395)
- Lots of fuzzying tests and changes to avoid panic on bad input data
- Support for SMPTE-2086 Mastering Display Metadata Box (SmDm)
- Support for Content Light Level Box (CoLL)
- Better test coverage for VisualSampleEntryBox
- IsVideoNaluType functions in both avc and hevc packages
- Exported constants for ColrBox's ColorType
- mp4.NewFreeBox, mp4.NewSkipBox functions
- mp4.FreeBox.Payload method
- mp4.SencBox methods: SetPerSampleIVSize, PerSampleIVSize, and ReadButNotParsed
- Function mp4.CreateUnknownBox
- Functions mp4.NewTfrfBox and mp4.NewTfxdBox
- HEVC (hvc1) encryption
- AppendProtectRange function is now public
- Tfhd bit masks are now public (#423)
- Skip bytes support for AVCDecoderConfigurationRecord (#420)

### Fixed

- Support short ESDS without SLConfig descriptor (issue #393)
- HEVC Slice Header CollocatedFromL0Flag should be true by default
- Update to golangci-lint/v2 and fixed all warnings
- Remove more boxes when decrypting files (pr #424)

## [0.47.0] - 2024-11-12

### Changed

- CreatePrftBox now takes flags parameter
- PrftBox Info output
- Removed ReplaceChild method of StsdBox
- CreateHdlr name for timed metadata
- extension .m4s is interpreted as MP4 file in mp4ff-pslister
- moved mp4.GetVersion() to internal.GetVersion()

### Added

- NTP64 struct with methods to convert to time.Time
- Constants for PrftBox flags
- Unittest to all programs in [cmd](cmd) and [examples](examples).
- Documentation in doc.go files for all packages

### Fixed

- Allow missing optional DecoderSpecificInfo
- Avoid mp4.File.Mdat pointing to an empty mdat box
- `cmd/mp4ff-encrypt` did not parse command line
- `SeigSampleGroupEntry` calculated skipBytes incorrectly
- `cmd/mp4ff-pslister` did not parse annex B HEVC correctly
- error when decrypting and re-encrypting a segement (issue #378)

### Removed

- Too specific functions DumpWithSampleData and Fragment.DumpSampleData

## [0.46.0] - 2024-08-08

### Fixed

- mvhd, tkhd, and mdhd timestamps were off by one day
- allow other sbgp and sgpd types than seig with senc

### Added

- mvhd, tkhd, and mdhd methods to set and get creation and modification times
- Event Message boxes evte, emib, emeb
- GetBtrt method to StsdBox
- Btrt pointer attribute in AudioSampleEnntry
- stpp can be used as value to CreateEmptyTrak

## [0.45.1] - 2024-07-12

### Added

- Box decoder error messages include start position

### Fixed

- Overflow in calculating sample decode time
- elng box errononously did not include full box headers

## [0.45.0] - 2024-06-06

### Changed

- minimum Go version 1.16.
- ioutil imports replaced by io and os imports
- Info (mp4ff-info) output for esds boxes
- API of descriptors
- Parsing and info output for url boxes

### Fixed

- support for parsing of hierarchical sidx boxes
- handling of partially bad descriptors
- handle url boxes missing mandatory zero-ending byte

### Added

- support for ssix box
- support for leva box
- details of descriptors as Info outout (mp4ff-info)

## [0.44.0] - 2024-04-19

### Added

- New `TryDecodeMfro` function
- New `mp4ff-subslister` tool replacing `mp4ff-wvttlister`. It supports `wvtt` and `stpp`
- `File.UpdateSidx()` to update or add a top level sidx box for a fragmented file
- `mp4.DecStartSegmentOnMoof` flag to make the Decoder interpret every moof as
  a new segment start, unless styp, sidx, or mfra boxes give that information.
- New example `add-sidx` shows how on can add a top-level `sidx` box to a fragmented file.
  It further has the option to remove unused encryption boxes, and to interpret each
  moof box as starting a new segment.
- New method `MoovBox.IsEncrypted()` checks if an encrypted codec is signaled

### Fixed

- More robust check for mfro at the end of file
- GetTrex() return value
- Can now write PIFF `uuid` box that has previously been read
- Does now avoid the second parsing of `senc` box if the file is ot encrypted as seen in moov box.

### Removed

- mp4ff-wvttlister tool removed and replaced by mp4ff-subslister

## [0.43.0] - 2024-04-04

### Added

- InitSegment.TweakSingleTrakLive changes an init segment to fit live streaming
- Made bits.Mask() function public
- New counter methods added to bits.Reader
- colr box support for nclc and unknown colour_type
- av01, encv, and enca direct pointers in stsd

### Changed

- All readers and writers in bits package now stop working at first error and provides the first error as AccError()
- Renamed bits.AccErrReader, bits.AccErrEBSPReader, bits.AccErrWriter to corresponiding names without AccErr
- Renamed bits.SliceWriterError to bits.ErrSliceWrite
- colr box supports unknown colrType

### Fixed

- kind box full-box header
- stpp support when the optional fields do not have a zero-termination byte
- mp4ff-wvttlister now lists all boxes in a sample

## [0.42.0] - 2024-01-26

### Fixed

- Support avc3 sample description when encrypting
- Full ProfileLevelTier parsing for HEVC
- Make pssh UUID comparison case-insensitive

### Added

- W3C Common PSSH Box UUID
- HEVC PicTiming SEI message parsing
- JSON marshaling of AVC PicTiming SEI message

## [0.41.0] - 2024-01-12

### Added

- Support for decrypting PIFF-encrypted segments

### Fixed

- Parsing of AVCDecoderConfigurationRecord
- Parsing of time offset in AVC PicTiming SEI
- Set senc.perSampleIVSize properly

## [0.40.2] - 2023-11-17

### Fixed

- Test of AVC PicTiming SEI with cbpDbpDelay set
- mp4ff-nallister has nicer output for annexb streams
- mp4ff-nallister handles AVC PicTiming SEI with cbpDbpDelay set

## [0.40.1] - 2023-11-01

### Fixed

- Swap of parameters in mp4ff-decrypt

## [0.40.0] - 2023-10-28

### Added

- New CLI app: mp4ff-encrypt to encrypt segments
- New CLI app: mp4ff-decrypt to decrypt segments
- New encyption-related functions in mp4
  - GetAVCProtectRanges to fine protection ranges for AVC video
  - CryptSampleCenc for encrypting of decrypting with cenc scheme
  - EncryptSampleCbcs - for encrypting with cbcs scheme
  - DecryptSampleCbcs - for decrypting with cbcs scheme
  - InitProtect to protect an init segment
  - EncryptFragment to encrypt a fragment
  - DecryptInit to extract and remove  decryption info from an init segment
  - DecryptFragment to decrypt a fragment
  - ExtractInitProtect to generate data needed for encryption
- AccErrEBSPReader.NrBitsRead method
- PsshBoxesFromBase64 and PsshBoxesFromBytes functions

### Fixed

- SPS.ChromaArrayType method
- Makefile now builds all CLI applications with version
- DecryptInit extracts pssh boxes

### Changed

- Removed examples/decrypt-cenc and instead made cmd/mp4ff-decrypt

## [0.39.0] - 2023-10-13

### Changed

- TfraEntry Time and MoofOffset types changed to unsigned
- TfraEntr attribute name SampleDelta corrected to SampleNumber

### Added

- MediaSegment and Fragment have new StartPos attribute
- mp4.File now has Mfra pointer
- MfraBox has new method FindEntry
- MediaSegment, Fragment, and Trun method CommonSampleDuration
- Added two MSS UUID constants

### Fixed

- fix AVC slice header parsing #272
- mp4ff-wvttlister works with Unified Streaming wvtt ismt file
- Fragment.GetFullSamples() allows tfdt to be absent
- Fragment.GetFullSamples() defaults to offset being moof
- mp4ff-wvttlister works for Unified Streaming wvtt asset
- mp4crop now crops elst entries
- mp4crop now handles multiple sample durations correctly
- HEVC SPS parsing details

## [0.38.1] - 2023-09-22

### Fixed

- ReadMP4File() failed when mfro not present

## [0.38.0] - 2023-09-06

### Added

- Loudness boxes `ludt`, `tlou`, and `alou`
- Description boxes `desc`, `©cpy`, `©nam`, `©ART` boxes
- `GenericContainerBox` struct
- new `DecFileFlags` provide option to `DecodeFile` to look for mfra box

### Changed

- Made `©too` use `GenericContainerBox`
- SidxBox got new attribute `AnchorPoint`

### Fixed

- DecodeFile uses sidx or mfra data to find segment boundaries

## [0.37.0] - 2023-08-14

### Added

- Pointer to stpp sample entry in StsdBox
- Doc strings for pointers in StsdBox

### Fixed

- discard of parsing HEVC SPS data
- `SttsBox.GetSampleNrAtTime` now supports a final zero sample duration

## [0.36.0] - 2023-06-07

### Changed

- SEI NAL unit parser reports ErrRbspTrailingBitsMissing error together with NAL units
- mp4ff-nallister reports error and SEI data when `rbsp_trailing_bits` are missing
- AVC SPS HRD parameter name corrected to DpbOutputDelayLengthMinus1

### Fixed

- Add WriteFlag method to SliceWriter interface (present in FixedSliceWriter)
- Parsing of AVC SEI pic_timing with HRD parameters
- mp4ff-nallister handles AVC SEI pic_timing with HRD parameters if SPS is present
- fix error in TimeOffset output of SEI 136

### Added

- Support for SEI message 1 pic_timing for AVC
- Example `combine-segs` that shows how to multiplex init and media segments into multi-track segments

## [0.35.0] - 2023-04-18

### Fixed

- `stpp` box handles optional empty lists properly (a single zero byte)
- AVC slice size value

### Added

- Exported function: `bits.CeilLog2`
- PPS parsing for HEVC
- `mp4ff-pslister` now provides PPS details for HEVC
- `mp4ff-pslister` now extracts inband parameter sets in progressive mp4 files
- Complete parsing of HEVC SPS extensions
- Parsing of HEVC slice header
- `SetType` method for `mp4.AudioSampleEntryBox`

## [0.34.1] - 2023-03-09

### Fixed

- Only start new segment at start or styp box

## [0.34.0] - 2023-02-28

### Added

- New function: `mp4.NewMediaSegmentWithStyp()`
- Associate emsg boxes with fragments
- New Fragment method: `AddEmsg()`
- `colr` box support
- CHANGELOG.md (this file) instead of Versions.md
- More tests

### Fixed

- Bugs in FixedSliceReader: ReadUint24 and LookAhead

### Changed

- Optimized translation from Annex B (start-code separated) video byte streams into length-field
  separated one
- Output of cenc example changed with styp boxes not included
- ADTS parsing somewhat more robust
- LastFragment() returns nil if no fragment in Segment
- Makefile target `coverage`

## [0.33.2] - 2023-01-26

### Changed

- Restored parsing of non-complete mdat box to v0.33.0 behavior, where a partial
  mdat box is not an error

## [0.33.1] - 2023-01-25

### Fixed

- Added missing parsing of sps_scaling_list_data_present_flag in HEVC SPS

## [0.33.0] - 2023-01-25

### Added

- Support QuickTime meta box as well as ISOBMFF meta box
- New possibility to disable parsing of specific boxes

## [0.32.0] - 2023-01-05

### Changed

- Moved repo to github.com/Eyevinn/mp4ff

### Deprecated

- The github.com/edgeware package path (but redirected by GitHub)

## [0.31.0] - 2022-12-28

### Changed

- Support multiple sidx
- Optimize stsc lookups
- New return type for NewNaluArray

### Fixed

- Fixed bugs in prft, adts and avc interlace

## [0.30.1] - 2022-11-06

### Fixed

- Fixed optimized sample copying bug introduced in v0.30.0

## [0.30.0] - 2022-11-04

### Added

- Full AVC slice header parsing.
- Complete set of AVC and HEVC SEI message detection
- Parsing of some SEI messages (136, 137, 144)
- Write of SEI message (#182)
- Optimizations in ctts and sample copying
- More byte stream methods
- mp4ff-pslister can now work on mp4 segments
- New functions for extracting NALUs for AVC and HEVC
- Optimized ctts lookup
- Optimized file.CopySampleData output allocations

### Fixed

- mp4ff-nallister NALU output
- emsg parsing
- HEVC nalu array bug
- Overflow in tfdt time (#177)

## [0.29.0] - 2022-06-21

### Changed

- Improved uuid box handling
- Improved esds box and underlying descriptor handling
- Extended decryption example with cbcs encryption
- Improved the decryption example with in-place cenc decryption

## [0.28.0] - 2022-05-12

### Added

- Full HEVC SPS parsing

### Changed

- Better video sample entry generation
- More AC-3/EC-3 support.
- Extended EBSPWriter
- Optimize: struct field alignments in bits package

### Fixed

- sdtp reference in StblBox
- decrypt-cenc example
- mp4ff-crop bad command line parameters

## [0.27.0] - 2022-03-06

### Added

- New more efficient SliceReader/SliceWriter based Box methods
- AC-3 and Enhanced AC-3 support

### Changed

- Public trun flag bits
- Public DecodeHeader method and BoxHeader structure
- mp4ff-nallister now takes Annex B byte stream
- mp4ff-pslister now takes Annex B byte stream and prints codec string

### Fixed

- mp4ff-crop stss bug
- ffmpeg data box decode
- stsz uniform size decode

## [0.26.1] - 2022-01-14

### Fixed

- Don't move trak boxes to be before mvex

## [0.26.0] - 2022-01-13

### Added

- New tool mp4ff-crop for cropping mp4 file
- New example decrypt-cenc for decrypting segment
- SEI parsing for H.264
- Interpret timestamps in mvhd, tkhd, and mdhd

## [0.25.0] - 2021-10-04

### Added

- Size() methods added to InitSegment, Fragment and MediaSegment
- SampleIntervals for more efficient transformation of segments
- Slices of samples and fullsamples
- Create init segments for wvtt and stpp

### Changed

- Improvements to ctts and stts boxes
- Changed sample slices to remove pointers
- Spell out compositionTimeOffset instead of cto
- More efficient code to check for AVC and HEVC parameter sets

## [0.24.0] - 2021-06-26

### Added

- Support for cslg and ©too boxes

### Changed

- DecodeFile API change to allow for lazy mdat decode
- segmenter example extension with lazy mode for decode and encode
- StssBox.IsSyncSample thread safe

## [0.23.1] - 2021-05-20

### Fixed

- Fixed segment encode mode without optimization

## [0.23.0] - 2021-04-30

### Changed

- API change: Verbatim encode more flexible with FragEncMode and EncOptimize

## [0.22.0] - 2021-04-23

### Added

- Construct AVC and HEVC codec strings from SPS

### Changed

- More robust parsing of ADTS

## [0.21.1] - 2021-03-24

### Fixed

- Allow ADTS ID corresponding to MPEG-2

## [0.21.0] - 2021-03-18

### Added

- Version number can be retrieved from cmd apps and from mp4 library.

### Changed

- Updated version is inserted as cmd apps are built using top-level Makefile.

## [0.20.0] - 2021-03-09

### Added

- New tool `mp4ff-pslister` for SPS and other parameter sets

## [0.19.0] - 2021-03-08

### Added

- Added mfra, mfro, tfra boxes
- Added kind, trep, skip, ilst boxes

### Fixed

- Fix for double trun-optimization

## [0.18.0] - 2021-01-26

### Added

- New tool `mp4ff-wvttlister` lists details of wvtt (WebVTT in ISOBMFF) samples
- More functions and methods for HEVC video handling

### Fixed

## [0.17.1] - 2021-01-19

### Fixed

- Fixed bugs in encoding/decoding hvcC box and HEVCDecoderConfigurationRecord

## [0.17.0] - 2021-01-15

### Added

- Support for HEVC/H.265 video parsing and encoding of boxes.
- New tool `mp4ff-nallister` to list nal units inside video samples in MP4 files.
- Support for multi-track fragmented files including new example
- Support for some new boxes: meta, udta, pasp, clap

### Changed

- mp4ff-pslister updated to support HEVC and reading parameter sets from byte streams and hex strings
- Improvements to Info output from mp4ff-info

## [0.16.2] - 2021-01-05

### Fixed

- Fixed and clarified that sample number starts at one

## [0.16.1] - 2021-01-04

### Fixed

- Fixed isNonSync flag definition
- Use sdtp entries and transfer to sample flags in segmenter example

## [0.16.0] - 2020-12-31

### Added

- New tool `mp4ff-info` prints details of a hierarchy of boxes. Has configurable levels of details
- Many new boxes: saio, saiz, enca, encv, frma, schm, schi, sinf, tenc, sbgp, sgpd, sdtp
- Support for writing largesize mdat box, even for smaller sizes
- Support for adts encode and decode

### Changed

- Much more detailed box info via recursive Info method
- Better tests vs golden files that can be updated with -update flag
- More error robustness in aac reading with new AccErrReader
- Replaced some panic calls with return of errors

## [0.15.0] - 2020-12-09

### Changed

- API for AVC video to to allow multiple SPS.
- Some more NALU types identified.

### Fixed

- Bug in handling of start-code emulation prevention bytes

## [0.14.0] - 2020-12-09

### Added

- AVC Byte stream (Annex B) support

## [0.13.0] - 2020-11-17

### Fixed

- Removed non-standard log package dependency

## [0.12.0] - 2020-11-17

### Changed

- Complete parsing of AVC (H.264) SPS and PP

## [0.11.1] - 2020-11-13

### Fixed

- Made SPS parser more robust

## [0.11.0] - 2020-11-13

### Added

- Lots of stuff

## [0.10.1] - 2020-09-23

### Fixed

- First sample-flag in trun and traf boxes

## [0.10.0] - 2020-09-03

### Added

- First release tag on GitHub
- Lots of stuff

### Changed

- New unique repo name: `mp4ff`

[Unreleased]: https://github.com/Eyevinn/mp4ff/compare/v0.49.0...HEAD
[0.49.0]: https://github.com/Eyevinn/mp4ff/compare/v0.48.0...v0.49.0
[0.48.0]: https://github.com/Eyevinn/mp4ff/compare/v0.47.0...v0.48.0
[0.47.0]: https://github.com/Eyevinn/mp4ff/compare/v0.46.0...v0.47.0
[0.46.0]: https://github.com/Eyevinn/mp4ff/compare/v0.45.1...v0.46.0
[0.45.1]: https://github.com/Eyevinn/mp4ff/compare/v0.45.0...v0.45.1
[0.45.0]: https://github.com/Eyevinn/mp4ff/compare/v0.44.0...v0.45.0
[0.44.0]: https://github.com/Eyevinn/mp4ff/compare/v0.43.0...v0.44.0
[0.43.0]: https://github.com/Eyevinn/mp4ff/compare/v0.42.0...v0.43.0
[0.42.0]: https://github.com/Eyevinn/mp4ff/compare/v0.41.0...v0.42.0
[0.41.0]: https://github.com/Eyevinn/mp4ff/compare/v0.40.2...v0.41.0
[0.40.2]: https://github.com/Eyevinn/mp4ff/compare/v0.40.1...v0.40.2
[0.40.1]: https://github.com/Eyevinn/mp4ff/compare/v0.40.0...v0.40.1
[0.40.0]: https://github.com/Eyevinn/mp4ff/compare/v0.39.0...v0.40.0
[0.39.0]: https://github.com/Eyevinn/mp4ff/compare/v0.38.0...v0.39.0
[0.38.1]: https://github.com/Eyevinn/mp4ff/compare/v0.37.0...v0.38.0
[0.38.0]: https://github.com/Eyevinn/mp4ff/compare/v0.37.0...v0.38.0
[0.37.0]: https://github.com/Eyevinn/mp4ff/compare/v0.36.0...v0.37.0
[0.36.0]: https://github.com/Eyevinn/mp4ff/compare/v0.35.0...v0.36.0
[0.35.0]: https://github.com/Eyevinn/mp4ff/compare/v0.34.1...v0.35.0
[0.34.1]: https://github.com/Eyevinn/mp4ff/compare/v0.34.0...v0.34.1
[0.34.0]: https://github.com/Eyevinn/mp4ff/compare/v0.33.2...v0.34.0
[0.33.2]: https://github.com/Eyevinn/mp4ff/compare/v0.33.1...v0.33.2
[0.33.1]: https://github.com/Eyevinn/mp4ff/compare/v0.33.0...v0.33.1
[0.33.0]: https://github.com/Eyevinn/mp4ff/compare/v0.32.0...v0.33.0
[0.32.0]: https://github.com/Eyevinn/mp4ff/compare/v0.31.0...v0.32.0
[0.31.0]: https://github.com/Eyevinn/mp4ff/compare/v0.30.0...v0.31.0
[0.30.1]: https://github.com/Eyevinn/mp4ff/compare/v0.30.0...v0.30.1
[0.30.0]: https://github.com/Eyevinn/mp4ff/compare/v0.29.0...v0.30.0
[0.29.0]: https://github.com/Eyevinn/mp4ff/compare/v0.28.0...v0.29.0
[0.28.0]: https://github.com/Eyevinn/mp4ff/compare/v0.27.0...v0.28.0
[0.27.0]: https://github.com/Eyevinn/mp4ff/compare/v0.26.0...v0.27.0
[0.26.1]: https://github.com/Eyevinn/mp4ff/compare/v0.26.0...v0.26.1
[0.26.0]: https://github.com/Eyevinn/mp4ff/compare/v0.25.0...v0.26.0
[0.25.0]: https://github.com/Eyevinn/mp4ff/compare/v0.24.0...v0.25.0
[0.24.0]: https://github.com/Eyevinn/mp4ff/compare/v0.23.0...v0.24.0
[0.23.1]: https://github.com/Eyevinn/mp4ff/compare/v0.23.0...v0.23.1
[0.23.0]: https://github.com/Eyevinn/mp4ff/compare/v0.22.0...v0.23.0
[0.22.0]: https://github.com/Eyevinn/mp4ff/compare/v0.21.0...v0.22.0
[0.21.1]: https://github.com/Eyevinn/mp4ff/compare/v0.21.0...v0.21.1
[0.21.0]: https://github.com/Eyevinn/mp4ff/compare/v0.20.0...v0.21.0
[0.20.0]: https://github.com/Eyevinn/mp4ff/compare/v0.19.0...v0.20.0
[0.19.0]: https://github.com/Eyevinn/mp4ff/compare/v0.18.0...v0.19.0
[0.18.0]: https://github.com/Eyevinn/mp4ff/compare/v0.17.0...v0.18.0
[0.17.1]: https://github.com/Eyevinn/mp4ff/compare/v0.17.0...v0.17.1
[0.17.0]: https://github.com/Eyevinn/mp4ff/compare/v0.16.0...v0.17.0
[0.16.2]: https://github.com/Eyevinn/mp4ff/compare/v0.16.1...v0.16.2
[0.16.1]: https://github.com/Eyevinn/mp4ff/compare/v0.16.0...v0.16.1
[0.16.0]: https://github.com/Eyevinn/mp4ff/compare/v0.15.0...v0.16.0
[0.15.0]: https://github.com/Eyevinn/mp4ff/compare/v0.14.0...v0.15.0
[0.14.0]: https://github.com/Eyevinn/mp4ff/compare/v0.13.0...v0.14.0
[0.13.0]: https://github.com/Eyevinn/mp4ff/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/Eyevinn/mp4ff/compare/v0.11.0...v0.12.0
[0.11.1]: https://github.com/Eyevinn/mp4ff/compare/v0.11.0...v0.11.1
[0.11.0]: https://github.com/Eyevinn/mp4ff/compare/v0.10.0...v0.11.0
[0.10.1]: https://github.com/Eyevinn/mp4ff/compare/v0.10.0...v0.10.1
[0.10.0]: https://github.com/Eyevinn/mp4ff/compare/v0.9.0...v0.10.0
