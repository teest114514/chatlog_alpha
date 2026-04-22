package deepcopy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Copy_iface(t *testing.T) {
	t.Run("#1: iface carries nil", func(t *testing.T) {
		var v []int
		var s any = v
		var d any
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Nil(t, d)
	})

	t.Run("#2: iface of str -> iface", func(t *testing.T) {
		var s any = "100"
		var d any
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, "100", d)
	})

	t.Run("#3: iface of str -> str", func(t *testing.T) {
		var s any = "abc"
		var d string
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, "abc", d)
	})

	t.Run("#4: iface of struct -> iface", func(t *testing.T) {
		type SS struct {
			I int
			U uint
		}
		var s any = SS{
			I: 1,
			U: 2,
		}
		var d any
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, SS{I: 1, U: 2}, d.(SS))
	})

	t.Run("#5: iface of struct ptr -> iface", func(t *testing.T) {
		type SS struct {
			I int
			U uint
		}
		var s any = &SS{
			I: 1,
			U: 2,
		}
		var d any
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, &SS{I: 1, U: 2}, d.(*SS))
	})

	t.Run("#6: iface of slice -> iface", func(t *testing.T) {
		var s any = []int{1, 2, 3}
		var d any
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, []int{1, 2, 3}, d.([]int))
	})

	t.Run("#7: iface of slice ptr -> iface", func(t *testing.T) {
		var s any = &[]int{1, 2, 3}
		var d any
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, &[]int{1, 2, 3}, d.(*[]int))
	})

	t.Run("#8: iface of array -> iface", func(t *testing.T) {
		var s any = [3]int{1, 2, 3}
		var d any
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, [3]int{1, 2, 3}, d.([3]int))
	})

	t.Run("#9: slice of iface -> iface", func(t *testing.T) {
		var s []any = []any{1, 2, 3}
		var d any
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, []any{1, 2, 3}, d.([]any))
	})

	t.Run("#10: array of iface -> iface", func(t *testing.T) {
		var s [3]any = [3]any{1, 2, 3}
		var d any
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, [3]any{1, 2, 3}, d.([3]any))
	})

	t.Run("#11: iface of struct -> struct", func(t *testing.T) {
		type SS struct {
			I int
			U uint
		}
		type DD struct {
			I int
			U uint
		}
		var s any = SS{
			I: 1,
			U: 2,
		}
		var d DD
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, DD{I: 1, U: 2}, d)
	})

	t.Run("#12: iface of iface", func(t *testing.T) {
		var s2 any
		var s any = &s2
		var d any
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, &s2, d)
	})

	t.Run("#13: iface of iface", func(t *testing.T) {
		var s2 any = "abc"
		var s any = &s2
		var d string
		err := Copy(&d, s)
		assert.Nil(t, err)
		assert.Equal(t, "abc", d)
	})
}

func Test_Copy_iface_error(t *testing.T) {
	t.Run("#1: nil interface", func(t *testing.T) {
		var s any
		var d any
		err := Copy(&d, s)
		assert.ErrorIs(t, err, ErrValueInvalid)
	})

	t.Run("#2: iface of str -> int", func(t *testing.T) {
		var s any = "100"
		var d int
		err := Copy(&d, s)
		assert.ErrorIs(t, err, ErrTypeNonCopyable)
	})

	t.Run("#3: iface of chan -> iface", func(t *testing.T) {
		ch := make(chan int, 10)
		var s any = ch
		var d any
		err := Copy(&d, s)
		assert.ErrorIs(t, err, ErrTypeNonCopyable)
	})
}
