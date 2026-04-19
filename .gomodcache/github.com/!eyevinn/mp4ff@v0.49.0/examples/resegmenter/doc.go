/*
resegmenter is an example on how to resegment a fragmented file to a new target segment duration.
The duration is given in ticks (in the track timescale).
If no init segment in the input, the trex defaults will not be known which may cause an issue.
The  input must be a fragmented file.

	Usage of resegmenter:
	resegmenter [options] infile outfile

	options:
	-d uint
			Required: chunk duration (ticks)
	-v    Verbose output

resegmenter is an example on how to resegment mp4 files into concatenated segments with new duration.
*/
package main
