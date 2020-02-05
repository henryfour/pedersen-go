package pedersen

import (
	"github.com/pkg/errors"
)

func getBitAt(index int, bytes []byte) (byte, error) {
	startByte := index / 8
	if startByte > len(bytes)-1 {
		return byte(0), errors.New("Index Surpass Bound")
	}
	bit := byte(0x80) >> uint((index % 8))
	if bytes[startByte]&bit == 0 {
		return 0, nil
	} else {
		return 1, nil
	}
}

func get3BitsAt(index int, bytes []byte) (byte, error) {
	firstBit, err := getBitAt(index, bytes)
	if err != nil {
		return firstBit, err
	}
	secondBit, err := getBitAt(index+1, bytes)
	if err != nil {
		return secondBit, err
	}
	thirdBit, err := getBitAt(index+2, bytes)
	if err != nil {
		return thirdBit, err
	}
	return (thirdBit << 2) | (secondBit << 1) | firstBit, nil
}

