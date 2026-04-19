/*
mp4ff-encrypt encrypts a fragmented mp4 file using Common Encryption with cenc or cbcs scheme.
A combined fragmented file with init segment and media segment(s) will be encrypted.
For a pure media segment, an init segment with encryption information is needed.
For video, only AVC with avc1 and HEVC with hvc1 sample entries are currently supported.
For audio, all supported audio codecs should work.

Usage of mp4ff-encrypt:

mp4ff-encrypt [options] infile outfile

options:

	-init string
	      Path to init file with encryption info (scheme, kid, pssh)
	-iv string
	      Required: iv (16 or 32 hex chars)
	-key string
	      Required: key (32 hex or 24 base64 chars)
	-kid string
	      key id (32 hex or 24 base64 chars). Required if initFilePath empty
	-pssh string
	      file with one or more pssh box(es) in binary format. Will be added at end of moov box
	-scheme string
	      cenc or cbcs. Required if initFilePath empty (default "cenc")
	-version
	      Get mp4ff version
*/
package main
