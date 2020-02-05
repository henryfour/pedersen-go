package pedersen

import (
	"crypto/sha256"
	"fmt"
	"github.com/pkg/errors"
	"math/big"
	"pedersen-go/babyjub"
)

// var sha256Hash = sha256.New()

func pedersenHashBasePoint(name string, i int) (*babyjub.Point, error) {
	if i > 0xFFFF {
		return nil, errors.New("Sequence number invalid")
	}
	if len(name) > 28 {
		return nil, errors.New("Name too long")
	}
	// data = b"%-28s%04X" % (name, i)
	formattedStr := fmt.Sprintf("%-28s%04X", name, i)
	data := []byte(formattedStr)

	sha256Hash := sha256.New()
	_, err := sha256Hash.Write(data)
	if err != nil {
		return nil, err
	}
	hashed := sha256Hash.Sum(nil)
	return babyjub.FromBytes(hashed)

}

func pedersenHashWindows(name string, windows []byte) (*babyjub.Point, error) {
	result := babyjub.Infinity()
	var current *babyjub.Point
	for j, window := range windows {
		var err error
		if j%62 == 0 {
			current, err = pedersenHashBasePoint(name, j/62)
			if err != nil {
				return nil, err
			}
		}
		j = j % 62
		if j != 0 {
			current = babyjub.NewPoint().Add(current, current)
			current = babyjub.NewPoint().Add(current, current)
			current = babyjub.NewPoint().Add(current, current)
			current = babyjub.NewPoint().Add(current, current)
		}
		segment := babyjub.NewPoint().Mul(big.NewInt(int64((window&0x3)+1)), current)
		if window > 0x3 {
			segment.X = segment.X.Neg(segment.X)
		}
		result = result.Add(result, segment)
	}
	return result, nil
}

func PedersenHashBytes(name string, bytes []byte) (*babyjub.Point, error) {
	if len(bytes) == 0 {
		return nil, errors.New("Cannot hash on null bytes")
	}
	// Split into 3 bit windows
	bitsLen := len(bytes) * 8
	windows := []byte{}
	for i := 0; i < bitsLen/3; i++ {
		result, err := get3BitsAt(i*3, bytes)
		if err != nil {
			return nil, err
		}
		windows = append(windows, result)
	}
	return pedersenHashWindows(name, windows)
}
