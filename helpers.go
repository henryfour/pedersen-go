package pedersen

import (
	"fmt"
	"github.com/pkg/errors"
)

func getBitAt(index int, bytes []byte) (byte, error) {
	startByte := index / 8
	if startByte > len(bytes)-1 {
		return byte(0), errors.New("out of index")
	}
	bit := byte(0x80) >> uint(index % 8)
	if bytes[startByte]&bit == 0 {
		return 0, nil
	} else {
		return 1, nil
	}
}

func get3BitsAt(index int, bytes []byte) (byte, error) {
	firstBit, err := getBitAt(index, bytes)
	if err != nil {
		return 0, err
	}
	secondBit, err := getBitAt(index+1, bytes)
	if err != nil {
		return firstBit, nil
	}
	thirdBit, err := getBitAt(index+2, bytes)
	if err != nil {
		return (secondBit << 1) | firstBit, nil
	}
	return (thirdBit << 2) | (secondBit << 1) | firstBit, nil
}

// Encode binary integer array to bytes.
// The input integer array can only contains elements of 0 or 1.
// This function can be used to convert the binary representation of the field array in zokrates.
// If the length is not a multiple of 8 then 0 is automatically added at the end.
func bitsToBytes(bits []byte) []byte {
	n := len(bits)
	if n == 0 {
		return []byte{}
	}
	for i := (n-1)%8 + 1; i < 8; i++ {
		bits = append(bits, 0)
	}
	bytes := make([]byte, n/8)
	for i, b := range bits {
		p := i / 8
		if b == 1 {
			bytes[p] |= byte(0x80) >> (i % 8)
		} else if b != 0 {
			panic(fmt.Errorf("invalid bit (%d)", i))
		}
	}
	return bytes
}

// This is the reverse conversion function of bitsToBytes
func bytesToBits(bytes []byte) []byte {
	bits := make([]byte, 8*len(bytes))
	p := 0
	for _, v := range bytes {
		for j := 0; j < 8; j ++ {
			if (v & (byte(0x80) >> j)) != 0 {
				bits[p] = 1
			}
			p++
		}
	}
	return bits
}
