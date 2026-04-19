// Copyright 2024 Garrett D'Amore
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use file except in compliance with the License.
// You may obtain a copy of the license at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package encoding

import (
	"errors"
	"testing"

	"golang.org/x/text/transform"
)

func TestUTF8(t *testing.T) {
	t.Logf("ASCII UTF8 identity transforms")
	for i := 0; i < 128; i++ {
		verifyMap(t, UTF8, byte(i), rune(i))
	}
}

func TestDstShortUTF8Decoder(t *testing.T) {
	decoder := ISO8859_1.NewDecoder()

	out := make([]byte, 1)
	nat := []byte{0xC0} // Latin1 A grave

	_, _, err := decoder.Transform(out, nat, true)
	if err == nil {
		t.Errorf("Passed but should not have")
	} else if !errors.Is(err, transform.ErrShortDst) {
		t.Errorf("Wrong error return: %v", err)
	}
}

func TestDstShortUTF8Encoder(t *testing.T) {

	encoder := UTF8.NewEncoder()
	nat := []byte("À")
	out := make([]byte, 1)
        _, _, err := encoder.Transform(out, nat, true)
        if err == nil {
                t.Errorf("Passed but should not have")
        } else if !errors.Is(err, transform.ErrShortDst) {
                t.Errorf("Wrong error return: %v", err)
        }
}

func TestSrcShortUTF8(t *testing.T) {
	encoder := ISO8859_1.NewEncoder()

	out := make([]byte, 2)
	nat := []byte("À")
	nat = nat[0:1]

	_, _, err := encoder.Transform(out, nat, true)
	if err == nil {
		t.Errorf("Passed but should not have: %v", nat)
	} else if !errors.Is(err, transform.ErrShortSrc) {
		t.Errorf("Wrong error return: %v %v", nat, err)
	}
}
