package encryption

import "errors"

const (
	Table_Size   = 0x400
	headXor      = 0xA5
	headXor2     = 0x18
	keyXor       = 0xAC
	CountSeed    = 0x76381
	KeyIndexMask = 0x3FF
)

func Decrypt(data []byte, table []byte) ([]byte, error) {
	if len(table) != Table_Size {
		return nil, errors.New("Key table is of wrong size.")
	}

	out := make([]byte, len(data))
	copy(out, data)

	if len(out) < 2 {
		return out, nil
	}

	out[0] ^= headXor
	out[1] ^= headXor2

	key := out[0] ^ keyXor
	ctr := uint32(out[1]^key) ^ CountSeed

	for i := len(out) - 1; i > 1; i-- {
		out[i] ^= table[(ctr&KeyIndexMask)^uint32(key)]
		ctr++
	}

	return out, nil
}

func Encrypt(data []byte, table []byte) ([]byte, error) {
	if len(table) != Table_Size {
		return nil, errors.New("Key table is of wrong size.")
	}

	out := make([]byte, len(data))
	copy(out, data)

	if len(out) < 2 {
		return out, nil
	}

	key := out[0] ^ keyXor
	ctr := uint32(out[1]^key) ^ CountSeed

	for i := len(out) - 1; i > 1; i-- {
		out[i] ^= table[(ctr&KeyIndexMask)^uint32(key)]
		ctr++
	}

	out[0] ^= headXor
	out[1] ^= headXor2

	return out, nil
}
