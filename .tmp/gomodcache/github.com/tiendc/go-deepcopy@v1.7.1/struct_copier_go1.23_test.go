//go:build go1.23

package deepcopy

import (
	"testing"
	"unique"

	"github.com/stretchr/testify/assert"
)

func Test_Copy_struct_on_standard_types_go1_23(t *testing.T) {
	t.Run("#1: Copy unique.Handle[string]", func(t *testing.T) {
		s := unique.Make("hello")
		var d unique.Handle[string]
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, d, s)
		assert.Equal(t, d.Value(), s.Value())

		// unique.Handle[T] as struct fields
		type A struct {
			I int
		}
		type S struct {
			H unique.Handle[A]
		}
		type D struct {
			H unique.Handle[A]
		}
		s2 := S{H: unique.Make(A{I: 111})}
		var d2 D
		err = Copy(&d2, s2)
		assert.Nil(t, err)
		assert.Equal(t, d2.H, s2.H)
		assert.Equal(t, d2.H.Value(), s2.H.Value())
	})

	t.Run("#2: Copy unique.Handle[string] to derived type", func(t *testing.T) {
		type T unique.Handle[string]
		s := unique.Make("hello")
		var d T
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, unique.Handle[string](d), s)
		assert.Equal(t, unique.Handle[string](d).Value(), s.Value())

		// unique.Handle[T] as struct fields
		type S struct {
			H unique.Handle[string]
		}
		type D struct {
			H T
		}
		s2 := S{H: unique.Make("hello")}
		var d2 D
		err = Copy(&d2, s2)
		assert.Nil(t, err)
		assert.Equal(t, unique.Handle[string](d2.H), s2.H)
		assert.Equal(t, unique.Handle[string](d2.H).Value(), s2.H.Value())
	})
}
