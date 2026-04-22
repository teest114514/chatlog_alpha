package deepcopy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Copy_ptr2ptr(t *testing.T) {
	t.Run("#1: int-ptr -> int-ptr", func(t *testing.T) {
		var s *int = ptrOf(111)
		var d *int
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, 111, *d)
		assert.True(t, d != s)
	})

	t.Run("#2: int-ptr -> int-ptr (dst has set)", func(t *testing.T) {
		var s *int = ptrOf(111)
		var d *int = ptrOf(222)
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, 111, *d)
		assert.True(t, d != s)
	})

	t.Run("#3: nil int-ptr -> int-ptr", func(t *testing.T) {
		var s *int
		var d *int
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Nil(t, d)
	})

	t.Run("#4: nil int-ptr -> int-ptr (dst has set)", func(t *testing.T) {
		var s *int
		var d *int = ptrOf(111)
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Nil(t, d)
	})
}

func Test_Copy_ptr2ptr_error(t *testing.T) {
	t.Run("#1: int-ptr -> struct-ptr (error)", func(t *testing.T) {
		type DD struct {
			I int
		}
		var s *int = ptrOf(111)
		var d *DD
		err := Copy(&d, s)
		assert.ErrorIs(t, err, ErrTypeNonCopyable)
	})
}

func Test_Copy_ptr2value(t *testing.T) {
	t.Run("#1: int-ptr -> int", func(t *testing.T) {
		var s *int = ptrOf(111)
		var d int
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, 111, d)
	})

	t.Run("#2: int-ptr -> int (dst has set)", func(t *testing.T) {
		var s *int = ptrOf(111)
		var d int = 222
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, 111, d)
	})

	t.Run("#3: nil int-ptr -> int", func(t *testing.T) {
		var s *int
		var d int = 111
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, 0, d)
	})
}

func Test_Copy_ptr2value_error(t *testing.T) {
	t.Run("#1: int-ptr -> struct (error)", func(t *testing.T) {
		type DD struct {
			I int
		}
		var s *int = ptrOf(111)
		var d DD
		err := Copy(&d, s)
		assert.ErrorIs(t, err, ErrTypeNonCopyable)
	})

	t.Run("#2: ptr -> value not allow", func(t *testing.T) {
		var s *int = ptrOf(111)
		var d int
		err := Copy(&d, s, func(ctx *Context) {
			ctx.CopyBetweenPtrAndValue = false
		})
		assert.ErrorIs(t, err, ErrTypeNonCopyable)
	})
}

func Test_Copy_value2ptr(t *testing.T) {
	t.Run("#1: int -> int-ptr", func(t *testing.T) {
		var s int = 111
		var d *int
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, 111, *d)
	})

	t.Run("#2: int -> int-ptr (dst has set)", func(t *testing.T) {
		var s int = 111
		var d *int = ptrOf(222)
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, 111, *d)
	})
}

func Test_Copy_value2ptr_error(t *testing.T) {
	t.Run("#1: int -> struct-ptr (error)", func(t *testing.T) {
		type DD struct {
			I int
		}
		var s int = 111
		var d *DD
		err := Copy(&d, s)
		assert.ErrorIs(t, err, ErrTypeNonCopyable)
	})

	t.Run("#2: value -> ptr not allow", func(t *testing.T) {
		var s int = 111
		var d *int
		err := Copy(&d, s, func(ctx *Context) {
			ctx.CopyBetweenPtrAndValue = false
		})
		assert.ErrorIs(t, err, ErrTypeNonCopyable)
	})
}

func Test_Copy_basicTypes(t *testing.T) {
	t.Run("#1: int -> int", func(t *testing.T) {
		var s int = 111
		var d int
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, 111, d)
	})

	t.Run("#2: int -> IntT", func(t *testing.T) {
		var s int = 111
		var d IntT
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, IntT(111), d)
	})

	t.Run("#3: int -> float64", func(t *testing.T) {
		var s int = 111
		var d float64
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, float64(111), d)
	})

	t.Run("#4: float64 -> int", func(t *testing.T) {
		var s float64 = 111.111
		var d int
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, 111, d)
	})

	t.Run("#5: string -> StrT", func(t *testing.T) {
		var s string = "abc"
		var d StrT
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, StrT("abc"), d)
	})

	t.Run("#6: func -> func", func(t *testing.T) {
		var s = func(i int) int {
			return i * 2
		}
		var d func(int) int
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, 2, d(1))
	})
}

func Test_Copy_basicTypes_error(t *testing.T) {
	t.Run("#1: nil dst", func(t *testing.T) {
		var s int = 111
		var d *int
		err := Copy(d, s)
		assert.ErrorIs(t, err, ErrValueInvalid)
	})

	t.Run("#2: func -> func (unmatched)", func(t *testing.T) {
		var s = func(i int) int {
			return i * 2
		}
		var d func(int) float32
		err := Copy(&d, s)
		assert.ErrorIs(t, err, ErrTypeNonCopyable)
	})
}
