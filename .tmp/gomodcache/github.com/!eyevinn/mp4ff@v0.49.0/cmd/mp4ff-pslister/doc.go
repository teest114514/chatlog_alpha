/*
mp4ff-pslister lists parameter sets for AVC/H.264 or HEVC/H.265 from mp4 sample description, bytestream, or hex input.
It prints them as hex and in verbose mode it also prints details in JSON format.

	Usage of mp4ff-pslister:

		mp4ff-pslister [options]

	options:

		-c string
			Codec to parse (avc or hevc) (default "avc")
		-i string
			Input file (mp4 or byte stream) (alternative to sps and pps in hex format)
		-pps string
			PPS in hex format
		-sps string
			SPS in hex format, alternative to infile
		-v	Verbose output -> details. On for hex input
		-version
			Get mp4ff version
		-vps string
			VPS in hex format (HEVC only)
*/
package main
