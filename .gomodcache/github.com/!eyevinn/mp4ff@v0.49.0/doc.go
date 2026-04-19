/*
Module mp4ff implements MP4 media file parsing and writing for AVC and HEVC video, AAC and AC-3 audio, stpp and wvtt subtitles, and
timed metadata tracks.
It is focused on fragmented files as used for streaming in MPEG-DASH, MSS and HLS fMP4, but can also decode and encode all
boxes needed for progressive MP4 files.

# Command Line Tools

Some useful command line tools are available in [cmd](cmd) directory.
 1. [mp4ff-info] prints a tree of the box hierarchy of a mp4 file with information
    about the boxes.
 2. [mp4ff-pslister] extracts and displays SPS and PPS for AVC or HEVC in a mp4 or a bytestream (Annex B) file.
    Partial information is printed for HEVC.
 3. [mp4ff-nallister] lists NALUs and picture types for video in progressive or fragmented file
 4. [mp4ff-subslister] lists details of wvtt or stpp (WebVTT or TTML in ISOBMFF) subtitle samples
 5. [mp4ff-crop] crops a **progressive** mp4 file to a specified duration
 6. [mp4ff-encrypt] encrypts a fragmented file using cenc or cbcs Common Encryption scheme
 7. [mp4ff-decrypt] decrypts a fragmented file encrypted using cenc or cbcs Common Encryption scheme

You can install these tools by going to their respective directory and run `go install .` or directly from the repo with

	go install github.com/Eyevinn/mp4ff/cmd/mp4ff-info@latest
	go install github.com/Eyevinn/mp4ff/cmd/mp4ff-encrypt@latests

for each individual tool.

# Example code

Example code for some common use cases is available in the [examples](examples) directory.
The examples and their functions are:

 1. [initcreator] creates typical init segments (ftyp + moov) for different video and
    audio codecs
 2. [resegmenter] reads a segmented file (CMAF track) and resegments it with other
    segment durations using `FullSample`
 3. [segmenter] takes a progressive mp4 file and creates init and media segments from it.
    This tool has been extended to support generation of segments with multiple tracks as well
    as reading and writing `mdat` in lazy mode
 4. [multitrack] parses a fragmented file with multiple tracks
 5. [combine-segs] combines single-track init and media segments into multi-track segments
 6. [add-sidx] adds a top-level sidx box describing the segments of a fragmented files.

# Packages

The top-level packages in the mp4ff module are

 1. [mp4] provides support for for parsing (called Decode) and writing (Encode) a plethor of mp4 boxes.
    It also contains helper functions for extracting, encrypting, dectrypting samples and a lot more.
 2. [avc] deals with AVC (aka H.264) video in the `mp4ff/avc` package including parsing of SPS and PPS,
    and finding start-codes in Annex B byte streams.
 3. [hevc] provides structures and functions for dealing with HEVC video and its packaging
 4. [sei] provides support for handling  Supplementary Enhancement Information (SEI) such as timestamps
    for AVC and HEVC video.
 5. [av1] provides basic support for AV1 video packaging
 6. [aac] provides support for AAC audio. This includes handling ADTS headers which is common
    for AAC inside MPEG-2 TS streams.
 7. [bits] provides bit-wise and byte-wise readers and writers used by the other packages.

# Specifications

The main specification for the MP4 file format is the ISO Base Media File Format (ISOBMFF) standard
ISO/IEC 14496-12 7th edition 2021. Some boxes are specified in other standards, as should be commented
in the code.

[mp4]: https://pkg.go.dev/github.com/Eyevinn/mp4ff/mp4
[avc]: https://pkg.go.dev/github.com/Eyevinn/mp4ff/avc
[hevc]: https://pkg.go.dev/github.com/Eyevinn/mp4ff/hevc
[sei]: https://pkg.go.dev/github.com/Eyevinn/mp4ff/sei
[av1]: https://pkg.go.dev/github.com/Eyevinn/mp4ff/av1
[aac]: https://pkg.go.dev/github.com/Eyevinn/mp4ff/aac
[bits]: https://pkg.go.dev/github.com/Eyevinn/mp4ff/bits
[initcreator]: https://pkg.go.dev/github.com/Eyevinn/mp4ff/examples/initcreator
[resegmenter]: https://pkg.go.dev/github.com/Eyevinn/mp4ff/examples/resegmenter
[segmenter]: https://pkg.go.dev/github.com/Eyevinn/mp4ff/examples/segmenter
[multitrack]: https://pkg.go.dev/github.com/Eyevinn/mp4ff/examples/multitrack
[combine-segs]: https://pkg.go.dev/github.com/Eyevinn/mp4ff/examples/combine-segs
[add-sidx]: https://pkg.go.dev/github.com/Eyevinn/mp4ff/examples/add-sidx
[mp4ff-info]: https://pkg.go.dev/github.com/Eyevinn/mp4ff/cmd/mp4ff-info
[mp4ff-pslister]: https://pkg.go.dev/github.com/Eyevinn/mp4ff/cmd/mp4ff-pslister
[mp4ff-nallister]: https://pkg.go.dev/github.com/Eyevinn/mp4ff/cmd/mp4ff-nallister
[mp4ff-subslister]: https://pkg.go.dev/github.com/Eyevinn/mp4ff/cmd/mp4ff-subslister
[mp4ff-crop]: https://pkg.go.dev/github.com/Eyevinn/mp4ff/cmd/mp4ff-crop
[mp4ff-encrypt]: https://pkg.go.dev/github.com/Eyevinn/mp4ff/cmd/mp4ff-encrypt
[mp4ff-decrypt]: https://pkg.go.dev/github.com/Eyevinn/mp4ff/cmd/mp4ff-decrypt
*/
package mp4ff
