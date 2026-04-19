/*
add-sidx shows how to add a top-level sidx box to a fragmented file provided it does not exist.
Segments are identified by styp boxes if they exist, otherwise by
the start of moof or emsg boxes. It is possible to interpret
every moof box as the start of a new segment, by specifying the "-startSegOnMoof" option.
One can further remove unused encryption boxes with the "-removeEnc" option.

	Usage of add-sidx:

		add-sidx [options] infile outfile

	options:

		-nzEPT
			Use non-zero earliestPresentationTime
		-removeEnc
			Remove unused encryption boxes
		-startSegOnMoof
			Start a new segment on every moof
		-version
			Get mp4ff version
*/
package main
