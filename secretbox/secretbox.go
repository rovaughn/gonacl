package secretbox

// #cgo LDFLAGS: -lsodium
// #include <sodium.h>
import "C"
import (
	"unsafe"
)

const (
	MacSize   = C.crypto_secretbox_MACBYTES
	NonceSize = C.crypto_secretbox_NONCEBYTES
	KeySize   = C.crypto_secretbox_KEYBYTES
)

func Seal(ciphertext, message, nonce, key []byte) {
	if len(ciphertext) != MacSize+len(message) {
		panic("ciphertext must be MacSize + len(message) bytes")
	}

	if len(nonce) != NonceSize {
		panic("nonce must be NonceSize bytes")
	}

	if len(key) != KeySize {
		panic("key must be KeySize bytes")
	}

	if C.crypto_secretbox_easy(
		(*C.uchar)(unsafe.Pointer(&ciphertext[0])),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.ulonglong(len(message)),
		(*C.uchar)(unsafe.Pointer(&nonce[0])),
		(*C.uchar)(unsafe.Pointer(&key[0])),
	) != 0 {
		panic("crypto_secretbox_easy returned an invalid code")
	}
}

func Open(message, ciphertext, nonce, key []byte) bool {
	if len(message) != len(ciphertext)-MacSize {
		panic("message must be len(ciphertext) - MacSize bytes")
	}

	if len(nonce) != C.crypto_secretbox_NONCEBYTES {
		panic("nonce must be NonceSize bytes")
	}

	if len(key) != C.crypto_secretbox_KEYBYTES {
		panic("key must be KeySize bytes")
	}

	if result := C.crypto_secretbox_open_easy(
		(*C.uchar)(unsafe.Pointer(&message[0])),
		(*C.uchar)(unsafe.Pointer(&ciphertext[0])),
		C.ulonglong(len(ciphertext)),
		(*C.uchar)(unsafe.Pointer(&nonce[0])),
		(*C.uchar)(unsafe.Pointer(&key[0])),
	); result == 0 {
		return true
	} else if result == -1 {
		return false
	} else {
		panic("crypto_secretbox_open_easy returned an invalid code")
	}
}
