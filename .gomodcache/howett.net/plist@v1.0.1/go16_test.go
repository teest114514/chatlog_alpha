// +build !go1.7

package plist

import "testing"

func subtest(t *testing.T, name string, f func(t *testing.T)) {
	// Subtests don't exist for Go <1.7, and we can't create our own testing.T to substitute in
	// for f's argument.
	f(t)
}
