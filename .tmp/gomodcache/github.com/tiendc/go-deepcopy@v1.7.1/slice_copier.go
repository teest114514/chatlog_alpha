package deepcopy

import (
	"reflect"
)

// sliceCopier data structure of copier that copies from a `slice`
type sliceCopier struct {
	ctx        *Context
	itemCopier copier
}

// Copy implementation of Copy function for slice copier
func (c *sliceCopier) Copy(dst, src reflect.Value) error {
	srcLen := src.Len()
	if dst.Kind() == reflect.Slice { // Slice/Array -> Slice
		// `src` is nil slice, set `dst` nil
		if src.Kind() == reflect.Slice && src.IsNil() {
			dst.Set(reflect.Zero(dst.Type())) // NOTE: Go1.18 has no SetZero
			return nil
		}
		newSlice := reflect.MakeSlice(dst.Type(), srcLen, srcLen)
		for i := 0; i < srcLen; i++ {
			if err := c.itemCopier.Copy(newSlice.Index(i), src.Index(i)); err != nil {
				return err
			}
		}
		dst.Set(newSlice)
		return nil
	}

	// Slice/Array -> Array
	dstLen := dst.Len()
	if dstLen < srcLen {
		srcLen = dstLen
	}
	i := 0
	for ; i < srcLen; i++ {
		if err := c.itemCopier.Copy(dst.Index(i), src.Index(i)); err != nil {
			return err
		}
	}
	for ; i < dstLen; i++ {
		item := dst.Index(i)
		item.Set(reflect.Zero(item.Type())) // NOTE: Go1.18 has no SetZero
	}
	return nil
}

func (c *sliceCopier) init(dstType, srcType reflect.Type) (err error) {
	c.itemCopier, err = buildCopier(c.ctx, dstType.Elem(), srcType.Elem())
	return
}
