package deepcopy

import (
	"reflect"
	"strings"
)

var (
	errType   = reflect.TypeOf((*error)(nil)).Elem()
	ifaceType = reflect.TypeOf((*any)(nil)).Elem()
	strType   = reflect.TypeOf((*string)(nil)).Elem()
)

const (
	typeMethodPostCopy = "PostCopy"
)

// typeParseMethods collects all copying methods from the given type
func typeParseMethods(ctx *Context, typ reflect.Type) (
	copyingMethods map[string]*reflect.Method, postCopyMethod *reflect.Method) {
	ptrType := reflect.PointerTo(typ)
	numMethods := ptrType.NumMethod()
	copyingMethods = make(map[string]*reflect.Method, numMethods)
	for i := 0; i < numMethods; i++ {
		method := ptrType.Method(i)
		switch {
		// Field copying method name must be something like `Copy<something>`
		case ctx.CopyViaCopyingMethod && strings.HasPrefix(method.Name, "Copy"):
			if method.Type.NumIn() != 2 || method.Type.NumOut() != 1 {
				continue
			}
			if method.Type.Out(0) != errType {
				continue
			}
			copyingMethods[method.Name] = &method

		// The method is for `post-copy` event
		case method.Name == typeMethodPostCopy:
			if method.Type.NumIn() != 2 || method.Type.NumOut() != 1 {
				continue
			}
			if method.Type.In(1) != ifaceType {
				continue
			}
			if method.Type.Out(0) != errType {
				continue
			}
			postCopyMethod = &method
		}
	}
	if len(copyingMethods) == 0 {
		copyingMethods = nil
	}
	return copyingMethods, postCopyMethod
}

// structParseAllFields parses all fields of a struct including direct fields and fields inherited from embedded structs
func structParseAllFields(typ reflect.Type) (
	directFieldKeys []string,
	mapDirectFields map[string]*fieldDetail,
	inheritedFieldKeys []string,
	mapInheritedFields map[string]*fieldDetail,
) {
	numFields := typ.NumField()
	directFieldKeys = make([]string, 0, numFields)
	mapDirectFields = make(map[string]*fieldDetail, numFields)
	inheritedFieldKeys = make([]string, 0, numFields)
	mapInheritedFields = make(map[string]*fieldDetail, numFields)

	for i := 0; i < numFields; i++ {
		sf := typ.Field(i)
		fDetail := &fieldDetail{field: &sf, index: []int{i}}
		parseTag(fDetail)
		if fDetail.ignored {
			continue
		}
		directFieldKeys = append(directFieldKeys, fDetail.key)
		mapDirectFields[fDetail.key] = fDetail

		// Parse embedded struct to get its fields
		if sf.Anonymous {
			for key, detail := range structParseAllNestedFields(sf.Type, fDetail.index) {
				inheritedFieldKeys = append(inheritedFieldKeys, key)
				mapInheritedFields[key] = detail
				fDetail.nestedFields = append(fDetail.nestedFields, detail)
			}
		}
	}
	return directFieldKeys, mapDirectFields, inheritedFieldKeys, mapInheritedFields
}

// structParseAllNestedFields parses all fields with initial index of starting field
func structParseAllNestedFields(typ reflect.Type, index []int) map[string]*fieldDetail {
	if typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if typ.Kind() != reflect.Struct {
		return nil
	}
	numFields := typ.NumField()
	result := make(map[string]*fieldDetail, numFields)

	for i := 0; i < numFields; i++ {
		sf := typ.Field(i)
		fDetail := &fieldDetail{field: &sf, index: append(index, i)}
		parseTag(fDetail)
		if fDetail.ignored {
			continue
		}
		result[fDetail.key] = fDetail
		// Parse embedded struct recursively to get its fields
		if sf.Anonymous {
			for key, detail := range structParseAllNestedFields(sf.Type, fDetail.index) {
				result[key] = detail
				fDetail.nestedFields = append(fDetail.nestedFields, detail)
			}
		}
	}
	return result
}

// structFieldGetWithInit gets deep nested field with init value for pointer ones
func structFieldGetWithInit(field reflect.Value, index []int) reflect.Value {
	for _, idx := range index {
		if field.Kind() == reflect.Pointer {
			if field.IsNil() {
				field.Set(reflect.New(field.Type().Elem()))
			}
			field = field.Elem()
		}
		field = field.Field(idx)
	}
	return field
}

// structFieldSetZero sets zero to a deep nested field
func structFieldSetZero(field reflect.Value, index []int) {
	field, err := field.FieldByIndexErr(index)
	if err == nil && field.IsValid() {
		field.Set(reflect.Zero(field.Type())) // NOTE: Go1.18 has no SetZero
	}
}

// nillableValueSetNilOnZero sets value as `nil` when its inner value is zero.
// Only applies to `Pointer`, `Interface`, `Slice` and `Map` types.
func nillableValueSetNilOnZero(val reflect.Value) {
	innerVal := val
	for {
		switch innerVal.Kind() { //nolint:exhaustive
		case reflect.Pointer, reflect.Interface:
			innerVal = innerVal.Elem()
			if !innerVal.IsValid() || innerVal.IsZero() {
				val.Set(reflect.Zero(val.Type())) // NOTE: Go1.18 has no SetZero
				return
			}
		case reflect.Slice, reflect.Map:
			if innerVal.Len() == 0 {
				val.Set(reflect.Zero(val.Type())) // NOTE: Go1.18 has no SetZero
			}
			return // always return as we can't go deeper with a slice or map
		default:
			return
		}
	}
}
