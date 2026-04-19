package deepcopy

import (
	"fmt"
	"reflect"
	"strings"
	"unsafe"
)

// mapToStructCopier data structure of copier that copies a map to a struct
type mapToStructCopier struct {
	ctx                     *Context
	mapDstCopyingMethod     map[string]*reflect.Method
	mapDstStructFields      map[string]*simpleFieldDetail
	dstStructRequiredFields int
	postCopyMethod          *int
}

type simpleFieldDetail struct {
	fieldType       reflect.Type
	fieldUnexported bool
	key             string
	required        bool
	nilOnZero       bool
	index           []int
}

// Copy implementation of Copy function for map to struct copier
//
//nolint:gocognit,gocyclo
func (c *mapToStructCopier) Copy(dstStruct, srcMap reflect.Value) error {
	if !srcMap.IsValid() || srcMap.IsNil() {
		return nil
	}

	dstStructType := dstStruct.Type()
	// Marks all fields of the dst struct which require copying
	var mapCopiedKeys map[string]struct{}
	if c.dstStructRequiredFields > 0 {
		mapCopiedKeys = make(map[string]struct{}, c.dstStructRequiredFields)
	}

	// Copies map entries to struct fields
	iter := srcMap.MapRange()
	for iter.Next() {
		key := iter.Key()
		srcVal := iter.Value()
		srcValType := srcVal.Type()
		keyStr := key.String()

		// Copying methods have higher priority, so if a method defined in the destination, use it
		if c.mapDstCopyingMethod != nil {
			methodName := "Copy" + strings.ToUpper(keyStr[:1]) + keyStr[1:]
			dstCpMethod, exists := c.mapDstCopyingMethod[methodName]
			if exists && !dstCpMethod.Type.In(1).AssignableTo(srcValType) {
				return fmt.Errorf("%w: struct method '%v.%s' does not accept argument type '%v' from '%v[%s]'",
					ErrMethodInvalid, dstStructType, dstCpMethod.Name, srcValType, srcMap.Type(), keyStr)
			}
			if exists {
				err := (&methodCopier{dstMethod: dstCpMethod.Index}).Copy(dstStruct, srcVal)
				if err != nil {
					return err
				}
				continue
			}
		}

		// Find field details from `dst` having the key
		dfDetail := c.mapDstStructFields[keyStr]
		if dfDetail == nil {
			continue
		}

		entryCopier, err := c.buildCopier(dstStructType, srcValType, dfDetail)
		if err != nil {
			return err
		}
		err = entryCopier.Copy(dstStruct, srcVal)
		if err != nil {
			return err
		}

		// Marks the field as copied
		if dfDetail.required {
			mapCopiedKeys[dfDetail.key] = struct{}{}
		}
	}

	// Checks if any dst field requires copying
	if c.dstStructRequiredFields > 0 {
		for _, v := range c.mapDstStructFields {
			if !v.required {
				continue
			}
			if _, exists := mapCopiedKeys[v.key]; !exists {
				return fmt.Errorf("%w: struct field '%v[%s]' requires copying",
					ErrFieldRequireCopying, dstStructType, v.key)
			}
		}
	}

	// Executes post-copy function of the destination struct
	if c.postCopyMethod != nil {
		method := dstStruct.Addr().Method(*c.postCopyMethod)
		errVal := method.Call([]reflect.Value{srcMap})[0]
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

func (c *mapToStructCopier) init(dstType, srcType reflect.Type) (err error) {
	mapKeyType, mapValType := srcType.Key(), srcType.Elem()
	if mapKeyType.Kind() != reflect.String {
		if c.ctx.IgnoreNonCopyableTypes {
			return nil
		}
		return fmt.Errorf("%w: copying from 'map[%v]%v' to struct type '%v' requires map key type to be 'string'",
			ErrTypeNonCopyable, mapKeyType, mapValType, dstType)
	}

	var postCopyMethod *reflect.Method
	c.mapDstCopyingMethod, postCopyMethod = typeParseMethods(c.ctx, dstType)
	if postCopyMethod != nil {
		c.postCopyMethod = &postCopyMethod.Index
	}

	dstDirectFields, mapDstDirectFields, dstInheritedFields, mapDstInheritedFields := structParseAllFields(dstType)
	c.mapDstStructFields = make(map[string]*simpleFieldDetail, len(dstDirectFields)+len(dstInheritedFields))

	for _, key := range append(dstDirectFields, dstInheritedFields...) {
		dfDetail := mapDstDirectFields[key]
		if dfDetail == nil || dfDetail.field.Anonymous {
			dfDetail = mapDstInheritedFields[key]
		}
		if dfDetail == nil || dfDetail.ignored || dfDetail.done || dfDetail.field.Anonymous {
			continue
		}
		c.mapDstStructFields[dfDetail.key] = &simpleFieldDetail{
			key:             dfDetail.key,
			fieldType:       dfDetail.field.Type,
			fieldUnexported: !dfDetail.field.IsExported(),
			required:        dfDetail.required,
			nilOnZero:       dfDetail.nilOnZero,
			index:           dfDetail.index,
		}
		if dfDetail.required {
			c.dstStructRequiredFields++
		}
	}

	return nil
}

func (c *mapToStructCopier) buildCopier(dstStructType, srcValType reflect.Type,
	dstFieldDetail *simpleFieldDetail) (copier, error) {
	// OPTIMIZATION: buildCopier() can handle this nicely
	if simpleKindMask&(1<<srcValType.Kind()) > 0 {
		if srcValType == dstFieldDetail.fieldType {
			// NOTE: pass nil to unset custom copier and trigger direct copying.
			// We can pass `&directCopier{}` for the same result (but it's a bit slower).
			return c.createValue2FieldCopier(dstFieldDetail, nil), nil
		}
		if srcValType.ConvertibleTo(dstFieldDetail.fieldType) {
			return c.createValue2FieldCopier(dstFieldDetail, defaultConvCopier), nil
		}
	}

	cp, err := buildCopier(c.ctx, dstFieldDetail.fieldType, srcValType)
	if err != nil {
		// NOTE: If the copy is not required and the field is unexported, ignore the error
		if !dstFieldDetail.required && dstFieldDetail.fieldUnexported {
			return defaultNopCopier, nil
		}
		return nil, err
	}
	if c.ctx.IgnoreNonCopyableTypes && dstFieldDetail.required {
		_, isNopCopier := cp.(*nopCopier)
		if isNopCopier {
			return nil, fmt.Errorf("%w: struct field '%v[%s]' requires copying",
				ErrFieldRequireCopying, dstStructType, dstFieldDetail.key)
		}
	}
	return c.createValue2FieldCopier(dstFieldDetail, cp), nil
}

func (c *mapToStructCopier) createValue2FieldCopier(df *simpleFieldDetail, cp copier) copier {
	return &value2StructFieldCopier{
		copier:               cp,
		dstFieldIndex:        df.index,
		dstFieldUnexported:   df.fieldUnexported,
		dstFieldSetNilOnZero: df.nilOnZero,
		required:             df.required || !df.fieldUnexported,
	}
}

// value2StructFieldCopier data structure of copier that copies from a value to a struct field
type value2StructFieldCopier struct {
	copier               copier
	dstFieldIndex        []int
	dstFieldUnexported   bool
	dstFieldSetNilOnZero bool
	required             bool
}

func (c *value2StructFieldCopier) Copy(dst, src reflect.Value) (err error) {
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
