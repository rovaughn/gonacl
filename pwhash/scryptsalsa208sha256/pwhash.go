package pwhash

// #cgo LDFLAGS: -lsodium
// #include <sodium.h>
import "C"
import (
	"bytes"
	"unsafe"
)

const (
	Size                = C.crypto_pwhash_STRBYTES
	OpsLimitSensitive   = C.crypto_pwhash_OPSLIMIT_SENSITIVE
	OpsLimitInteractive = C.crypto_pwhash_OPSLIMIT_INTERACTIVE
	MemLimitSensitive   = C.crypto_pwhash_MEMLIMIT_SENSITIVE
	MemLimitInteractive = C.crypto_pwhash_MEMLIMIT_INTERACTIVE
)

func Hash(hash []byte, password []byte, opslimit uint64, memlimit uint64) (int, bool) {
	if len(hash) != Size {
		panic("hash must be Size bytes")
	}

	if result := C.crypto_pwhash_scryptsalsa208sha256_str(
		(*C.char)(unsafe.Pointer(&hash[0])),
		(*C.char)(unsafe.Pointer(&password[0])),
		C.ulonglong(len(password)),
		C.ulonglong(opslimit),
		C.size_t(memlimit),
	); result == 0 {
		return bytes.IndexByte(hash, 0), true
	} else if result == -1 {
		return 0, false
	} else {
		panic("crypto_pwhash_scryptsalsa208sha256_str returned an invalid code")
	}
}

func Verify(hashedPassword, password []byte) bool {
	if result := C.crypto_pwhash_scryptsalsa208sha256_str_verify(
		(*C.char)(unsafe.Pointer(&hashedPassword[0])),
		(*C.char)(unsafe.Pointer(&password[0])),
		C.ulonglong(len(password)),
	); result == 0 {
		return true
	} else if result == -1 {
		return false
	} else {
		panic("crypto_pwhash_scryptsalsa208sha256_str_verify returned an invalid code")
	}
}
