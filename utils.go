package gothemis

import (
	"crypto/elliptic"
	"errors"
	"math"
	"math/big"
)

const (
	NISTCurvParamA = -3
	OddPointY      = 3
	evenPointY     = 2
)

func lengthInBytes(x * big.Int)int{
	return int(math.Ceil(float64(x.BitLen() / 8)))
}

func alignPointInBytes(size int, x *big.Int) []byte {
	keyDiffBitsSize := size*8 - x.BitLen()
	zeroByteCount := keyDiffBitsSize / 8
	output := make([]byte, zeroByteCount, size)
	return append(output, x.Bytes()...)

}

func CompressNISTPublicKey(curve elliptic.Curve, x, y *big.Int) []byte {
	keySizeInBytes := curve.Params().BitSize / 8
	output := make([]byte, 1+keySizeInBytes)
	switch y.Bit(0) {
	case 0:
		output[0] = evenPointY
	case 1:
		output[0] = OddPointY
	}
	xBytes := alignPointInBytes(keySizeInBytes, x)
	copy(output[1:], xBytes)
	return output
}

var ErrInvalidCompressedPointData = errors.New("invalid compressed point data")

// UncompressNISTPublicKey decompress point according to Point Compression Technique X9.62 Section 4.2.1
func UncompressNISTPublicKey(curve elliptic.Curve, compressedData []byte) (x, y *big.Int, err error) {
	if compressedData[0] != evenPointY && compressedData[0] != OddPointY {
		return nil, nil, errors.New("incorrect PC value")
	}

	x = new(big.Int).SetBytes(compressedData[1:])

	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)

	threeX := new(big.Int).Lsh(x, 1)
	threeX.Add(threeX, x)

	x3.Sub(x3, threeX)
	x3.Add(x3, curve.Params().B)
	//x3.Mod(x3, curve.Params().P)

	// square root mod P
	y = new(big.Int).ModSqrt(x3, curve.Params().P)

	if y == nil {
		return nil, nil, ErrInvalidCompressedPointData
	}

	yBit := uint(compressedData[0] & 1)
	if y.Bit(0) != yBit {
		y.Neg(y)
		y.Mod(y, curve.Params().P)

		// y == Beta
		//y.Sub(curve.Params().P, y)
		if y.Bit(0) != yBit {
			return nil, nil, errors.New("incorrect result of P-B")
		}
	}
	if !curve.IsOnCurve(x, y) {
		err = errors.New("points is not on the curve")
	}
	return
}

func Zeroize(data []byte) {
	for i := 0; i < len(data); i++ {
		data[i] = 0
	}
}
