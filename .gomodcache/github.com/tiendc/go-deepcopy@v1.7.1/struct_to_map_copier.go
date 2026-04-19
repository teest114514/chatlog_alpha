package deepcopy

import (
	"fmt"
	"reflect"
	"strings"
	"unsafe"
)

// structToMapCopier data structure of copier that copies a `struct` to a map
type structToMapCopier struct {
	ctx            *Context
	fieldCopiers   []copier
	postCopyMethod *int
}

// Copy implementation of Copy function for struct to map copier
func (c *structToMapCopier) Copy(dst, src reflect.Value) error {
	// Inits destination map
	if dst.IsNil() {
		dst.Set(reflect.MakeMapWithSize(dst.Type(), len(c.fieldCopiers)))
	}
	// Copies struct fields to map
	for _, cp := range c.fieldCopiers {
		if err := cp.Copy(dst, src); err != nil {
			return err
		}
	}
	// Executes post-copy function of the destination map
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

func (c *structToMapCopier) init(dstType, srcType reflect.Type) (err error) {
	mapKeyType, mapValType := dstType.Key(), dstType.Elem()
	mapKeyNeedConvert := false
	switch {
	case strType.AssignableTo(mapKeyType):
	case strType.ConvertibleTo(mapKeyType):
		mapKeyNeedConvert = true
	default:
		if c.ctx.IgnoreNonCopyableTypes {
			return nil
		}
		return fmt.Errorf("%w: copying from struct type '%v' to 'map[%v]%v' requires map key type to be 'string'",
			ErrTypeNonCopyable, srcType, mapKeyType, mapValType)
	}

	dstCopyingMethods, postCopyMethod := typeParseMethods(c.ctx, dstType)
	if postCopyMethod != nil {
		c.postCopyMethod = &postCopyMethod.Index
	}

	srcDirectFields, mapSrcDirectFields, srcInheritedFields, mapSrcInheritedFields := structParseAllFields(srcType)
	c.fieldCopiers = make([]copier, 0, len(srcDirectFields)+len(srcInheritedFields))

	for _, key := range append(srcDirectFields, srcInheritedFields...) {
		// Find field details from `src` having the key
		sfDetail := mapSrcDirectFields[key]
		if sfDetail == nil {
			sfDetail = mapSrcInheritedFields[key]
		}
		if sfDetail == nil || sfDetail.ignored || sfDetail.done || sfDetail.field.Anonymous {
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

		copier, err := c.buildCopier(mapKeyType, mapValType, srcType, sfDetail, mapKeyNeedConvert)
		if err != nil {
			return err
		}
		c.fieldCopiers = append(c.fieldCopiers, copier)
		sfDetail.markDone()
	}

	return nil
}

func (c *structToMapCopier) buildCopier(mapKeyType, mapValueType, srcStructType reflect.Type,
	srcFieldDetail *fieldDetail, mapKeyNeedConvert bool) (copier, error) {
	sf := srcFieldDetail.field

	mapKey := reflect.ValueOf(srcFieldDetail.key)
	if mapKeyNeedConvert {
		mapKey = mapKey.Convert(mapKeyType)
	}

	// OPTIMIZATION: buildCopier() can handle this nicely
	if simpleKindMask&(1<<sf.Type.Kind()) > 0 {
		if sf.Type == mapValueType {
			// NOTE: pass nil to unset custom copier and trigger direct copying.
			// We can pass `&directCopier{}` for the same result (but it's a bit slower).
			return c.createField2MapEntryCopier(srcFieldDetail, mapKey, nil), nil
		}
		if sf.Type.ConvertibleTo(mapValueType) {
			return c.createField2MapEntryCopier(srcFieldDetail, mapKey,
				&mapItemCopier{dstType: mapValueType, copier: defaultConvCopier}), nil
		}
	}

	cp, err := buildCopier(c.ctx, mapValueType, sf.Type)
	if err != nil {
		// NOTE: If the copy is not required and the field is unexported, ignore the error
		if !srcFieldDetail.required && !sf.IsExported() {
			return defaultNopCopier, nil
		}
		return nil, err
	}
	if c.ctx.IgnoreNonCopyableTypes && srcFieldDetail.required {
		_, isNopCopier := cp.(*nopCopier)
		if isNopCopier {
			return nil, fmt.Errorf("%w: struct field '%v[%s]' requires copying",
				ErrFieldRequireCopying, srcStructType, srcFieldDetail.field.Name)
		}
	}
	return c.createField2MapEntryCopier(srcFieldDetail, mapKey,
		&mapItemCopier{dstType: mapValueType, copier: cp}), nil
}

func (c *structToMapCopier) createField2MethodCopier(dM *reflect.Method, sfDetail *fieldDetail) copier {
	return &structField2MethodCopier{
		dstMethod:          dM.Index,
		srcFieldIndex:      sfDetail.index,
		srcFieldUnexported: !sfDetail.field.IsExported(),
		required:           sfDetail.required || sfDetail.field.IsExported(),
	}
}

func (c *structToMapCopier) createField2MapEntryCopier(sf *fieldDetail, key reflect.Value,
	valueCopier *mapItemCopier) copier {
	return &structField2MapEntryCopier{
		key:                key,
		valueCopier:        valueCopier,
		srcFieldIndex:      sf.index,
		srcFieldUnexported: !sf.field.IsExported(),
		required:           sf.required || sf.field.IsExported(),
	}
}

// structField2MapEntryCopier data structure of copier that copies from
// a src field to the destination map
type structField2MapEntryCopier struct {
	key                reflect.Value
	valueCopier        *mapItemCopier
	srcFieldIndex      []int
	srcFieldUnexported bool
	required           bool
}

// Copy implementation of Copy function for struct field copier direct.
// NOTE: `dst` and `src` are struct values.
func (c *structField2MapEntryCopier) Copy(dst, src reflect.Value) (err error) {
	if len(c.srcFieldIndex) == 1 {
		src = src.Field(c.srcFieldIndex[0])
	} else {
		// NOTE: When a struct pointer is embedded (e.g. type StructX struct { *BaseStruct }),
		// this retrieval can fail if the embedded struct pointer is nil. Just skip copying when fails.
		src, err = src.FieldByIndexErr(c.srcFieldIndex)
		if err != nil {
			// There's no src field to copy from, reset the dst field to zero
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

	if c.valueCopier != nil {
		if src, err = c.valueCopier.Copy(src); err != nil {
			if c.required {
				return err
			}
			return nil
		}
	}
	dst.SetMapIndex(c.key, src)

	return nil
}
