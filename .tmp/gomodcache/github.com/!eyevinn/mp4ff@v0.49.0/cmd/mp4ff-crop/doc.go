/*
mp4ff-crop crops a (progressive) mp4 file to just before a sync frame after specified number of milliseconds.
The goal is to leave the file structure intact except for cropping of samples and
moving mdat to the end of the file, if not already there.

	Usage of mp4ff-crop:

		mp4ff-crop [options] <inFile> <outFile>

	options:

		-d uint
			Duration in milliseconds (default 1000)
		-version
			Get mp4ff version
*/
package main
