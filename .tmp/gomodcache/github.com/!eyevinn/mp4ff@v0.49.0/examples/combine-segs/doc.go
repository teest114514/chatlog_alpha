/*
combine-segs provides an example of multiplexing tracks from fragmented MP4 files.
It combines init and media segments from two different files into a single
multitrack init or media segment. The functions

	combineInitSegments
	combineMediaSegments

combines the tracks from two or more different init or media segments.
The combined tracks get unique track names as specified using parameters.
Note that they should start at 1 according to the file format specification.

In principle, the `trex` box data from the init segment may be needed when
generating media segments since that may contain default values. In practice,
for this specific case of just transfering tracks, it should work without
propagating the `trex` data.

The data is written to the combined `mdat` box track by track, so that there
is exactly one `trun` box for each track. Interleaving data into more `trun`
boxes should be possible by writing fractions of samples from the different
input files.
*/
package main
