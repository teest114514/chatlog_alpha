/*
segmenter segments a progressive mp4 file into init and media segments.
The output is either single-track segments, or muxed multi-track segments.
With the -lazy mode, mdat is read and written lazily. The lazy write
is only for single-track segments, to provide a comparison with the multi-track
implementation.

There should be at most one audio and one video track in the input.
The output files will be named as
init segments: <output>_a.mp4 and <output>_v.mp4
media segments: <output>_a_<n>.m4s and <output>_v_<n>.m4s where n >= 1
or init.mp4 and media_<n>.m4s

Codecs supported are AVC and HEVC for video and AAC
and AC-3 for audio.

	Usage of segmenter:

		segmenter [options] infile outfilePrefix

	options:

		-d uint
				Required: segment duration (milliseconds). The segments will start at syncSamples with decoded time >= n*segDur
		-lazy
				Read/write mdat lazily
		-m    Output multiplexed segments
		-v    Verbose output
*/
package main
