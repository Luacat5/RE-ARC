package main

import "errors"

const table_size = 0x400

func Decrypt(data []byte, table []byte) ([]byte, error) {
	if len(table) != table_size {
		return nil, errors.New("Key table is of wrong size.")
	}

	out := make([]byte, len(data))
	copy(out, data)

	if len(out) < 2 {
		return out, nil
	}

	out[0] ^= 0xA5
	out[1] ^= 0x18

	key := out[0] ^ 0xAC
	ctr := uint32(out[1]^key) ^ 0x76381

	for i := len(out) - 1; i > 1; i-- {
		out[i] ^= table[(ctr&0x3FF)^uint32(key)]
		ctr++
	}

	return out, nil
}

func Encrypt(data []byte, table []byte) ([]byte, error) {
	if len(table) != table_size {
		return nil, errors.New("Key table is of wrong size.")
	}

	out := make([]byte, len(data))
	copy(out, data)

	if len(out) < 2 {
		return out, nil
	}

	key := out[0] ^ 0xAC
	ctr := uint32(out[1]^key) ^ 0x76381

	for i := len(out) - 1; i > 1; i-- {
		out[i] ^= table[(ctr&0x3FF)^uint32(key)]
		ctr++
	}

	out[0] ^= 0xA5
	out[1] ^= 0x18

	return out, nil
}
