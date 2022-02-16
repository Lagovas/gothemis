package gothemis

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"

	"github.com/cossacklabs/acra/utils"
)

// getDataLengthFromAcraStruct unpack data length value from AcraStruct
func getDataLengthFromAcraStruct(data []byte) int {
	dataLengthBlock := data[GetMinAcraStructLength()-DataLengthSize : GetMinAcraStructLength()]
	return int(binary.LittleEndian.Uint64(dataLengthBlock))
}

// GetMinAcraStructLength returns minimal length of AcraStruct
// because in golang we can't declare byte array as constant we need to calculate length of TagBegin in runtime
// or hardcode as constant and maintain len(TagBegin) == CONST_VALUE
func GetMinAcraStructLength() int {
	return len(TagBegin) + KeyBlockLength + DataLengthSize
}

// Errors show incorrect AcraStruct length
var (
	ErrIncorrectAcraStructTagBegin   = errors.New("AcraStruct has incorrect TagBegin")
	ErrIncorrectAcraStructLength     = errors.New("AcraStruct has incorrect length")
	ErrIncorrectAcraStructDataLength = errors.New("AcraStruct has incorrect data length value")
)

// ValidateAcraStructLength check that data has minimal length for AcraStruct and data block equal to data length in AcraStruct
func ValidateAcraStructLength(data []byte) error {
	baseLength := GetMinAcraStructLength()
	if len(data) < baseLength {
		return ErrIncorrectAcraStructLength
	}
	if !bytes.Equal(data[:len(TagBegin)], TagBegin) {
		return ErrIncorrectAcraStructTagBegin
	}
	dataLength := getDataLengthFromAcraStruct(data)
	if dataLength != len(data[GetMinAcraStructLength():]) {
		return ErrIncorrectAcraStructDataLength
	}
	return nil
}

const (
	// TagSymbol used in begin tag in AcraStruct
	TagSymbol byte = '"'
)

// TagBegin represents begin sequence of bytes for AcraStruct.
var TagBegin = []byte{TagSymbol, TagSymbol, TagSymbol, TagSymbol, TagSymbol, TagSymbol, TagSymbol, TagSymbol}

const (
	// length of EC public key
	PublicKeyLength = 45
	// length of 32 byte of symmetric key wrapped to smessage
	SMessageKeyLength = 84
	KeyBlockLength    = PublicKeyLength + SMessageKeyLength

	SymmetricKeySize = 32
	// DataLengthSize length of part of AcraStruct that store data part length. So max data size is 2^^64 that
	// may be wrapped into AcraStruct. We decided that 2^^64 is enough and not much as 8 byte overhead per AcraStruct
	DataLengthSize = 8
)

// CreateAcrastruct encrypt your data using acra_public key and context (optional)
// and pack into correct Acrastruct format
func CreateAcrastruct(data []byte, acraPublic *PublicECKey, context []byte) ([]byte, error) {
	randomKeyPair, err := NewECKeyPair()
	if err != nil {
		return nil, err
	}
	publicKey, err := randomKeyPair.Public.Marshal()
	if err != nil {
		return nil, err
	}
	// generate random symmetric key
	randomKey := make([]byte, SymmetricKeySize)
	n, err := rand.Read(randomKey)
	if err != nil {
		return nil, err
	}
	if n != SymmetricKeySize {
		return nil, errors.New("read incorrect num of random bytes")
	}

	// create smessage for encrypting symmetric key
	smessage, err := NewSecureMessage(randomKeyPair.Private, acraPublic)
	if err != nil {
		return nil, err
	}
	encryptedKey, err := smessage.Wrap(randomKey)
	if err != nil {
		return nil, err
	}
	randomKeyPair.Private.Zeroize()

	// create scell for encrypting data
	encryptedData, err := CellSealEncrypt(randomKey, data, nil)
	if err != nil {
		return nil, err
	}
	Zeroize(randomKey)

	// pack acrastruct
	dateLength := make([]byte, DataLengthSize)
	binary.LittleEndian.PutUint64(dateLength, uint64(len(encryptedData)))
	output := make([]byte, len(TagBegin)+KeyBlockLength+DataLengthSize+len(encryptedData))
	output = append(output[:0], TagBegin...)
	output = append(output, publicKey...)
	output = append(output, encryptedKey...)
	output = append(output, dateLength...)
	output = append(output, encryptedData...)
	return output, nil
}

func DecryptAcrastruct(data []byte, privateKey *PrivateECKey, zone []byte) ([]byte, error) {
	if err := ValidateAcraStructLength(data); err != nil {
		return nil, err
	}
	innerData := data[len(TagBegin):]
	publicKey, err := UnmarshalThemisECPublicKey(innerData[:PublicKeyLength])
	if err != nil {
		return nil, err
	}

	smessage, err := NewSecureMessage(privateKey, publicKey)
	if err != nil {
		return nil, err
	}
	symmetricKey, err := smessage.Unwrap(innerData[PublicKeyLength:KeyBlockLength])
	if err != nil {
		return []byte{}, err
	}
	//
	var length uint64
	// convert from little endian
	err = binary.Read(bytes.NewReader(innerData[KeyBlockLength:KeyBlockLength+DataLengthSize]), binary.LittleEndian, &length)
	if err != nil {
		return []byte{}, err
	}

	decrypted, err := CellSealDecrypt(symmetricKey, innerData[KeyBlockLength+DataLengthSize:], zone)
	utils.ZeroizeBytes(symmetricKey)
	if err != nil {
		return nil, err
	}
	return decrypted, nil
}
