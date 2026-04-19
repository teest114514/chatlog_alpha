package errors

import "net/http"

var (
	ErrAlreadyDecrypted              = New(nil, http.StatusBadRequest, "database file is already decrypted")
	ErrDecryptHashVerificationFailed = New(nil, http.StatusBadRequest, "hash verification failed during decryption")
	ErrDecryptIncorrectKey           = New(nil, http.StatusBadRequest, "incorrect decryption key")
	ErrDecryptOperationCanceled      = New(nil, http.StatusBadRequest, "decryption operation was canceled")
	ErrNoMemoryRegionsFound          = New(nil, http.StatusBadRequest, "no memory regions found")
	ErrReadMemoryTimeout             = New(nil, http.StatusInternalServerError, "read memory timeout")
	ErrWeChatOffline                 = New(nil, http.StatusBadRequest, "WeChat is offline")
	ErrSIPEnabled                    = New(nil, http.StatusBadRequest, "SIP is enabled")
	ErrValidatorNotSet               = New(nil, http.StatusBadRequest, "validator not set")
	ErrNoValidKey                    = New(nil, http.StatusBadRequest, "no valid key found")
)

func PlatformUnsupported(platform string, version int) *Error {
	return Newf(nil, http.StatusBadRequest, "unsupported platform: %s v%d", platform, version).WithStack()
}

func DecryptCreateCipherFailed(cause error) *Error {
	return New(cause, http.StatusInternalServerError, "failed to create cipher").WithStack()
}

func DecodeKeyFailed(cause error) *Error {
	return New(cause, http.StatusBadRequest, "failed to decode hex key").WithStack()
}

func CreatePipeFileFailed(cause error) *Error {
	return New(cause, http.StatusInternalServerError, "failed to create pipe file").WithStack()
}

func OpenPipeFileFailed(cause error) *Error {
	return New(cause, http.StatusInternalServerError, "failed to open pipe file").WithStack()
}

func ReadPipeFileFailed(cause error) *Error {
	return New(cause, http.StatusInternalServerError, "failed to read from pipe file").WithStack()
}

func RunCmdFailed(cause error) *Error {
	return New(cause, http.StatusInternalServerError, "failed to run command").WithStack()
}

func ReadMemoryFailed(cause error) *Error {
	return New(cause, http.StatusInternalServerError, "failed to read memory").WithStack()
}

func OpenProcessFailed(cause error) *Error {
	return New(cause, http.StatusInternalServerError, "failed to open process").WithStack()
}

func WeChatAccountNotFound(name string) *Error {
	return Newf(nil, http.StatusBadRequest, "WeChat account not found: %s", name).WithStack()
}

func WeChatAccountNotOnline(name string) *Error {
	return Newf(nil, http.StatusBadRequest, "WeChat account is not online: %s", name).WithStack()
}

func RefreshProcessStatusFailed(cause error) *Error {
	return New(cause, http.StatusInternalServerError, "failed to refresh process status").WithStack()
}
