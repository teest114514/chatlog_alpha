/*
mp4ff-nallister lists NAL units and slice types of AVC or HEVC tracks of an mp4 (ISOBMFF) file
or a file containing a byte stream in Annex B format.

Takes first video track in a progressive file and the first track in a fragmented file.
It can also output information about SEI NAL units.

The parameter-sets can be further
analyzed using mp4ff-pslister.

	Usage of mp4ff-nallister:

		mp4ff-nallister [options] infile

	options:

		-annexb
			Input is Annex B stream file
		-c string
			Codec to parse (avc or hevc) (default "avc")
		-m int
			Max nr of samples to parse (default -1)
		-ps
			Print parameter sets in hex
		-raw int
			nr raw NAL unit bytes to print
		-sei int
			Level of SEI information (1 is interpret, 2 is dump hex)
		-version
			Get mp4ff version
*/
package main
