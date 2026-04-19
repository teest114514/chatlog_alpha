// Copyright 2024 Tobias Klauser. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris

package sysconf_cgotest

import (
	"runtime"
	"testing"
)

func testSysconfCgoMatch(t *testing.T) {
	t.Skipf("skipping cgotest on unsupported platform %s", runtime.GOOS)
}
