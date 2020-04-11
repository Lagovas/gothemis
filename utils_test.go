package gothemis

import (
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"testing"
)

func TestCompressNISTPublicKey(t *testing.T) {
	for i := 0; i < 1000; i++ {
		_, x, y, err := elliptic.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			fmt.Println(err)
		}
		if !elliptic.P256().IsOnCurve(x, y) {
			fmt.Println("generated points not on curve")
		}
		//fmt.Printf("\nx=%v\ny=%v\n", x.Bytes(), y.Bytes())
		compressed := CompressNISTPublicKey(elliptic.P256(), x, y)

		newX, newY, err := UncompressNISTPublicKey(elliptic.P256(), compressed)
		//t.Logf("\nnewX=%v\nnewY=%v\n", newX.Bytes(), newY.Bytes())
		if x.Cmp(newX) != 0 {
			fmt.Println("decompressed X point not equal")
		}
		if y.Cmp(newY) != 0 {
			fmt.Printf("decompressed Y point not equal, \nexpect: %v, \ntook: %v\n", y.Bytes(), newY.Bytes())
		}
		if err != nil {
			t.Fatal(err)
		}
	}
}
