package deepcopy

import (
	"fmt"
	"reflect"
)

// copier base interface defines Copy function
type copier interface {
	Copy(dst, src reflect.Value) error
}

// nopCopier no-op copier
type nopCopier struct {
}

// Copy implementation of Copy function for no-op copier
func (c *nopCopier) Copy(dst, src reflect.Value) error {
	return nil
}

var defaultNopCopier = &nopCopier{}

// value2PtrCopier data structure of copier that copies from a value to a pointer
type value2PtrCopier struct {
	ctx    *Context
	copier copier
}

// Copy implementation of Copy function for value-to-pointer copier
func (c *value2PtrCopier) Copy(dst, src reflect.Value) error {
	if dst.IsNil() {
		dst.Set(reflect.New(dst.Type().Elem()))
	}
	dst = dst.Elem()
	return c.copier.Copy(dst, src)
}

func (c *value2PtrCopier) init(dstType, srcType reflect.Type) (err error) {
	c.copier, err = buildCopier(c.ctx, dstType.Elem(), srcType)
	return
}

// ptr2ValueCopier data structure of copier that copies from a pointer to a value
type ptr2ValueCopier struct {
	ctx    *Context
	copier copier
}

// Copy implementation of Copy function for pointer-to-value copier
func (c *ptr2ValueCopier) Copy(dst, src reflect.Value) error {
	src = src.Elem()
	if !src.IsValid() {
		dst.Set(reflect.Zero(dst.Type())) // NOTE: Go1.18 has no SetZero
		return nil
	}
	return c.copier.Copy(dst, src)
}

func (c *ptr2ValueCopier) init(dstType, srcType reflect.Type) (err error) {
	c.copier, err = buildCopier(c.ctx, dstType, srcType.Elem())
	return
}

// ptr2PtrCopier data structure of copier that copies from a pointer to a pointer
type ptr2PtrCopier struct {
	ctx    *Context
	copier copier
}

// Copy implementation of Copy function for pointer-to-pointer copier
func (c *ptr2PtrCopier) Copy(dst, src reflect.Value) error {
	src = src.Elem()
	if !src.IsValid() {
		dst.Set(reflect.Zero(dst.Type())) // NOTE: Go1.18 has no SetZero
		return nil
	}
	if dst.IsNil() {
		dst.Set(reflect.New(dst.Type().Elem()))
	}
	dst = dst.Elem()
	return c.copier.Copy(dst, src)
}

func (c *ptr2PtrCopier) init(dstType, srcType reflect.Type) (err error) {
	c.copier, err = buildCopier(c.ctx, dstType.Elem(), srcType.Elem())
	return
}

// directCopier copier that does copying by assigning `src` value to `dst` directly
type directCopier struct {
}

func (c *directCopier) Copy(dst, src reflect.Value) error {
	dst.Set(src)
	return nil
}

var defaultDirectCopier = &directCopier{}

// convCopier copier that does copying with converting `src` value to `dst` type
type convCopier struct {
}

func (c *convCopier) Copy(dst, src reflect.Value) error {
	dst.Set(src.Convert(dst.Type()))
	return nil
}

var defaultConvCopier = &convCopier{}

// inlineCopier copier that does copying on the fly.
// This copier is usually used to avoid circular reference.
type inlineCopier struct {
	ctx     *Context
	dstType reflect.Type
	srcType reflect.Type
}

func (c *inlineCopier) Copy(dst, src reflect.Value) error {
	cp, err := buildCopier(c.ctx, c.dstType, c.srcType)
	if err != nil {
		return err
	}
	return cp.Copy(dst, src)
}

// methodCopier copier that calls a copying method
type methodCopier struct {
	dstMethod int
}

func (c *methodCopier) Copy(dst, src reflect.Value) (err error) {
	dst = dst.Addr().Method(c.dstMethod)
	errVal := dst.Call([]reflect.Value{src})[0]
	if errVal.IsNil() {
		return nil
	}
	err, ok := errVal.Interface().(error)
	if !ok {
		return fmt.Errorf("%w: copying method returned non-error value", ErrTypeInvalid)
	}
	return err
}
