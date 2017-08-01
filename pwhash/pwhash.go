package pwhash

// #cgo LDFLAGS: -lsodium
// #include <sodium.h>
import "C"
import (
	"bytes"
	"unsafe"
)

const (
	STRBYTES             = C.crypto_pwhash_STRBYTES
	OPSLIMIT_SENSITIVE   = C.crypto_pwhash_OPSLIMIT_SENSITIVE
	OPSLIMIT_INTERACTIVE = C.crypto_pwhash_OPSLIMIT_INTERACTIVE
	MEMLIMIT_SENSITIVE   = C.crypto_pwhash_MEMLIMIT_SENSITIVE
	MEMLIMIT_INTERACTIVE = C.crypto_pwhash_MEMLIMIT_INTERACTIVE
)

func Hash(password string, opslimit uint64, memlimit uint64) (string, bool) {
	str := make([]byte, C.crypto_pwhash_STRBYTES)
	if C.crypto_pwhash_str((*C.char)(unsafe.Pointer(&str[0])), C.CString(password), C.ulonglong(len(password)), C.ulonglong(opslimit), C.size_t(memlimit)) == 0 {
		return string(str[:bytes.IndexByte(str, 0)]), true
	} else {
		return "", false
	}
}

func Verify(hashedPassword, password string) bool {
	return C.crypto_pwhash_str_verify(C.CString(hashedPassword), C.CString(password), C.ulonglong(len(password))) == 0
}
