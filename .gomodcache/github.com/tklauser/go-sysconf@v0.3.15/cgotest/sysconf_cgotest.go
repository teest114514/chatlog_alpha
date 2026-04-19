// Copyright 2018 Tobias Klauser. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package sysconf_cgotest

/*
#include <unistd.h>
*/
import "C"

import (
	"testing"

	"github.com/tklauser/go-sysconf"
)

type testCase struct {
	goVar int
	cVar  C.int
	name  string
}

func testSysconfGoCgo(t *testing.T, tc testCase) {
	t.Helper()

	if tc.goVar != int(tc.cVar) {
		t.Errorf("SC_* parameter value for %v is %v, want %v", tc.name, tc.goVar, tc.cVar)
	}

	goVal, goErr := sysconf.Sysconf(tc.goVar)
	if goErr != nil {
		t.Errorf("Sysconf(%s/%d): %v", tc.name, tc.goVar, goErr)
		return
	}
	t.Logf("%s = %v", tc.name, goVal)

	cVal, cErr := C.sysconf(tc.cVar)
	if cErr != nil {
		t.Errorf("C.sysconf(%s/%d): %v", tc.name, tc.cVar, cErr)
		return
	}

	if goVal != int64(cVal) {
		t.Errorf("Sysconf(%v/%d) returned %v, want %v", tc.name, tc.goVar, goVal, cVal)
	}
}

func testSysconfGoCgoInvalid(t *testing.T, tc testCase) {
	t.Helper()

	if tc.goVar != int(tc.cVar) {
		t.Errorf("SC_* parameter value for %v is %v, want %v", tc.name, tc.goVar, tc.cVar)
	}

	_, goErr := sysconf.Sysconf(tc.goVar)
	if goErr == nil {
		t.Errorf("Sysconf(%s/%d) unexpectedly returned without error", tc.name, tc.goVar)
		return
	}

	_, cErr := C.sysconf(tc.cVar)
	if cErr == nil {
		t.Errorf("C.sysconf(%s/%d) unexpectedly returned without error", tc.name, tc.goVar)
	}
}
