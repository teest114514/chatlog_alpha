package deepcopy

import (
	"fmt"
	"reflect"
	"strings"
	"unsafe"
)

// structCopier data structure of copier that copies from a `struct`
type structCopier struct {
	ctx            *Context
	fieldCopiers   []copier
	postCopyMethod *int
}

// Copy implementation of Copy function for struct copier
func (c *structCopier) Copy(dst, src reflect.Value) error {
	for _, cp := range c.fieldCopiers {
		if err := cp.Copy(dst, src); err != nil {
			return err
		}
	}
	// Executes post-copy function of the destination struct
	if c.postCopyMethod != nil {
		dst = dst.Addr().Method(*c.postCopyMethod)
		errVal := dst.Call([]reflect.Value{src})[0]
		if errVal.IsNil() {
			return nil
		}
		err, ok := errVal.Interface().(error)
		if !ok { // Should never get in here
			return fmt.Errorf("%w: PostCopy method returns non-error value", ErrTypeInvalid)
		}
		return err
	}
	return nil
}

//nolint:gocognit,gocyclo
func (c *structCopier) init(dstType, srcType reflect.Type) (err error) {
	dstCopyingMethods, postCopyMethod := typeParseMethods(c.ctx, dstType)
	if postCopyMethod != nil {
		c.postCopyMethod = &postCopyMethod.Index
	}

	dstDirectFields, mapDstDirectFields, dstInheritedFields, mapDstInheritedFields := structParseAllFields(dstType)
	srcDirectFields, mapSrcDirectFields, srcInheritedFields, mapSrcInheritedFields := structParseAllFields(srcType)
	c.fieldCopiers = make([]copier, 0, len(dstDirectFields)+len(dstInheritedFields))

	for _, key := range append(srcDirectFields, srcInheritedFields...) {
		// Find field details from `src` having the key
		sfDetail := mapSrcDirectFields[key]
		if sfDetail == nil {
			sfDetail = mapSrcInheritedFields[key]
		}
		if sfDetail == nil || sfDetail.ignored || sfDetail.done {
			continue
		}

		// Copying methods have higher priority, so if a method defined in the dst struct, use it
		if dstCopyingMethods != nil {
			methodName := "Copy" + strings.ToUpper(key[:1]) + key[1:]
			dstCpMethod, exists := dstCopyingMethods[methodName]
			if exists && !dstCpMethod.Type.In(1).AssignableTo(sfDetail.field.Type) {
				return fmt.Errorf("%w: struct method '%v.%s' does not accept argument type '%v' from '%v[%s]'",
					ErrMethodInvalid, dstType, dstCpMethod.Name, sfDetail.field.Type, srcType, sfDetail.field.Name)
			}
			if exists {
				c.fieldCopiers = append(c.fieldCopiers, c.createField2MethodCopier(dstCpMethod, sfDetail))
				sfDetail.markDone()
				continue
			}
		}

		// Find field details from `dst` having the key
		dfDetail := mapDstDirectFields[key]
		if dfDetail == nil {
			dfDetail = mapDstInheritedFields[key]
		}
		if dfDetail == nil || dfDetail.ignored || dfDetail.done {
			// Found no corresponding dest field to copy to, raise an error in case this is required
			if sfDetail.required {
				return fmt.Errorf("%w: struct field '%v[%s]' requires copying",
					ErrFieldRequireCopying, srcType, sfDetail.field.Name)
			}
			continue
		}

		copier, err := c.buildCopier(dstType, srcType, dfDetail, sfDetail)
		if err != nil {
			return err
		}
		c.fieldCopiers = append(c.fieldCopiers, copier)
		dfDetail.markDone()
		sfDetail.markDone()
	}

	// Remaining dst fields can't be copied
	for _, dfDetail := range mapDstDirectFields {
		if !dfDetail.done && dfDetail.required {
			return fmt.Errorf("%w: struct field '%v[%s]' requires copying",
				ErrFieldRequireCopying, dstType, dfDetail.field.Name)
		}
	}
	for _, dfDetail := range mapDstInheritedFields {
		if !dfDetail.done && dfDetail.required {
			return fmt.Errorf("%w: struct field '%v[%s]' requires copying",
				ErrFieldRequireCopying, dstType, dfDetail.field.Name)
		}
	}

	return nil
}

func (c *structCopier) buildCopier(
	dstStructType, srcStructType reflect.Type,
	dstFieldDetail, srcFieldDetail *fieldDetail,
) (copier, error) {
	df, sf := dstFieldDetail.field, srcFieldDetail.field

	// OPTIMIZATION: buildCopier() can handle this nicely
	if simpleKindMask&(1<<sf.Type.Kind()) > 0 {
		if sf.Type == df.Type {
			// NOTE: pass nil to unset custom copier and trigger direct copying.
			// We can pass `&directCopier{}` for the same result (but it's a bit slower).
			return c.createField2FieldCopier(dstFieldDetail, srcFieldDetail, nil), nil
		}
		if sf.Type.ConvertibleTo(df.Type) {
			return c.createField2FieldCopier(dstFieldDetail, srcFieldDetail, defaultConvCopier), nil
		}
	}

	cp, err := buildCopier(c.ctx, df.Type, sf.Type)
	if err != nil {
		// NOTE: If the copy is not required and the field is unexported, ignore the error
		if !dstFieldDetail.required && !srcFieldDetail.required && !df.IsExported() {
			return defaultNopCopier, nil
		}
		return nil, err
	}
	if c.ctx.IgnoreNonCopyableTypes && (srcFieldDetail.required || dstFieldDetail.required) {
		_, isNopCopier := cp.(*nopCopier)
		if isNopCopier && dstFieldDetail.required {
			return nil, fmt.Errorf("%w: struct field '%v[%s]' requires copying",
				ErrFieldRequireCopying, dstStructType, dstFieldDetail.field.Name)
		}
		if isNopCopier && srcFieldDetail.required {
			return nil, fmt.Errorf("%w: struct field '%v[%s]' requires copying",
				ErrFieldRequireCopying, srcStructType, srcFieldDetail.field.Name)
		}
	}
	return c.createField2FieldCopier(dstFieldDetail, srcFieldDetail, cp), nil
}

func (c *structCopier) createField2MethodCopier(dM *reflect.Method, sfDetail *fieldDetail) copier {
	return &structField2MethodCopier{
		dstMethod:          dM.Index,
		srcFieldIndex:      sfDetail.index,
		srcFieldUnexported: !sfDetail.field.IsExported(),
		required:           sfDetail.required || sfDetail.field.IsExported(),
	}
}

func (c *structCopier) createField2FieldCopier(df, sf *fieldDetail, cp copier) copier {
	return &structField2FieldCopier{
		copier:               cp,
		dstFieldIndex:        df.index,
		dstFieldUnexported:   !df.field.IsExported(),
		dstFieldSetNilOnZero: df.nilOnZero,
		srcFieldIndex:        sf.index,
		srcFieldUnexported:   !sf.field.IsExported(),
		required:             sf.required || df.required || df.field.IsExported(),
	}
}

// structField2FieldCopier data structure of copier that copies from
// a src field to a dst field directly
type structField2FieldCopier struct {
	copier               copier
	dstFieldIndex        []int
	dstFieldUnexported   bool
	dstFieldSetNilOnZero bool
	srcFieldIndex        []int
	srcFieldUnexported   bool
	required             bool
}

// Copy implementation of Copy function for struct field copier direct.
// NOTE: `dst` and `src` are struct values.
func (c *structField2FieldCopier) Copy(dst, src reflect.Value) (err error) {
	if len(c.srcFieldIndex) == 1 {
		src = src.Field(c.srcFieldIndex[0])
	} else {
		// NOTE: When a struct pointer is embedded (e.g. type StructX struct { *BaseStruct }),
		// this retrieval can fail if the embedded struct pointer is nil. Just skip copying when fails.
		src, err = src.FieldByIndexErr(c.srcFieldIndex)
		if err != nil {
			// There's no src field to copy from, reset the dst field to zero
			structFieldSetZero(dst, c.dstFieldIndex)
			return nil //nolint:nilerr
		}
	}
	if c.srcFieldUnexported {
		if !src.CanAddr() {
			if c.required {
				return fmt.Errorf("%w: accessing unexported source field requires it to be addressable",
					ErrValueUnaddressable)
			}
			return nil
		}
		src = reflect.NewAt(src.Type(), unsafe.Pointer(src.UnsafeAddr())).Elem() //nolint:gosec
	}

	if len(c.dstFieldIndex) == 1 {
		dst = dst.Field(c.dstFieldIndex[0])
	} else {
		// Get dst field with making sure it's settable
		dst = structFieldGetWithInit(dst, c.dstFieldIndex)
	}
	if c.dstFieldUnexported {
		// NOTE: dst is always addressable as Copy() requires `dst` to be pointer
		dst = reflect.NewAt(dst.Type(), unsafe.Pointer(dst.UnsafeAddr())).Elem() //nolint:gosec
	}

	// Use custom copier if set
	if c.copier != nil {
		if err = c.copier.Copy(dst, src); err != nil {
			if c.required {
				return err
			}
			return nil
		}
	} else {
		// Otherwise, just perform simple direct copying
		dst.Set(src)
	}

	// When instructed to set `dst` as `nil` on zero
	if c.dstFieldSetNilOnZero {
		nillableValueSetNilOnZero(dst)
	}

	return nil
}

// structField2MethodCopier data structure of copier that copies between `fields` and `methods`
type structField2MethodCopier struct {
	dstMethod          int
	srcFieldIndex      []int
	srcFieldUnexported bool
	required           bool
}

// Copy implementation of Copy function for struct field copier between `fields` and `methods`.
// NOTE: `dst` and `src` are struct values.
func (c *structField2MethodCopier) Copy(dst, src reflect.Value) (err error) {
	if len(c.srcFieldIndex) == 1 {
		src = src.Field(c.srcFieldIndex[0])
	} else {
		// NOTE: When a struct pointer is embedded (e.g. type StructX struct { *BaseStruct }),
		// this retrieval can fail if the embedded struct pointer is nil. Just skip copying when fails.
		src, err = src.FieldByIndexErr(c.srcFieldIndex)
		if err != nil {
			return nil //nolint:nilerr
		}
	}
	if c.srcFieldUnexported {
		if !src.CanAddr() {
			if c.required {
				return fmt.Errorf("%w: accessing unexported source field requires it to be addressable",
					ErrValueUnaddressable)
			}
			return nil
		}
		src = reflect.NewAt(src.Type(), unsafe.Pointer(src.UnsafeAddr())).Elem() //nolint:gosec
	}

	dst = dst.Addr().Method(c.dstMethod)
	errVal := dst.Call([]reflect.Value{src})[0]
	if errVal.IsNil() {
		return nil
	}
	err, ok := errVal.Interface().(error)
	if !ok {
		return fmt.Errorf("%w: struct method returned non-error value", ErrTypeInvalid)
	}
	return err
}
