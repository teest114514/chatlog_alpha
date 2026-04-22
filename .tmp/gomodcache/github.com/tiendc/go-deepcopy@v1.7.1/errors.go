package deepcopy

import (
	"errors"
)

// Errors may be returned from Copy function
var (
	// ErrTypeInvalid returned when type of input var does not meet the requirement
	ErrTypeInvalid = errors.New("ErrTypeInvalid")
	// ErrTypeNonCopyable returned when the function can not perform copying between types
	ErrTypeNonCopyable = errors.New("ErrTypeNonCopyable")
	// ErrValueInvalid returned when input value does not meet the requirement
	ErrValueInvalid = errors.New("ErrValueInvalid")
	// ErrValueUnaddressable returned when value is `unaddressable` which is required
	// in some situations such as when accessing an unexported struct field.
	ErrValueUnaddressable = errors.New("ErrValueUnaddressable")
	// ErrFieldRequireCopying returned when a field is required to be copied
	// but no copying is done for it.
	ErrFieldRequireCopying = errors.New("ErrFieldRequireCopying")
	// ErrMethodInvalid returned when copying method of a struct is not valid
	ErrMethodInvalid = errors.New("ErrMethodInvalid")
)
