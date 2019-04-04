package gothemis

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"

	"golang.org/x/crypto/pbkdf2"
)

func min(a, b int) int {
	if a <= b {
		return a
	}
	return b
}

func themisKDF(key, label []byte, contexts [][]byte) []byte {
	out := []byte{0, 0, 0, 1}
	const implicitKeySize = 32
	implicitKey := make([]byte, implicitKeySize)
	if len(key) == 0 {
		copy(implicitKey, label[:min(implicitKeySize, len(label))])
		for _, context := range contexts {
			if len(context) > 0 {
				for j := 0; j < min(implicitKeySize, len(context)); j++ {
					implicitKey[j] ^= context[j]
				}
			}
		}
		key = implicitKey
	}
	hash := hmac.New(sha256.New, key)
	hash.Write(out[:4])
	hash.Write(label)
	hash.Write(out[:1])
	for _, context := range contexts {
		if len(context) > 0 {
			hash.Write(context)
		}
	}
	return hash.Sum(nil)
}

var THEMIS_SYM_KDF_KEY_LABEL = []byte("Themis secure cell message key")

const (
	SOTER_SYM_256_KEY_LENGTH uint32 = 0x00000100
	SOTER_SYM_AES_GCM        uint32 = 0x40010000
	SOTER_SYM_KDF_MASK       uint32 = 0x0f000000
	SOTER_SYM_NOKDF          uint32 = 0x00000000

	SOTER_SYM_PBKDF2 uint32 = 0x01000000

	THEMIS_AUTH_SYM_KEY_LENGTH      uint32 = SOTER_SYM_256_KEY_LENGTH
	THEMIS_AUTH_SYM_ALG             uint32 = SOTER_SYM_AES_GCM | THEMIS_AUTH_SYM_KEY_LENGTH
	THEMIS_AUTH_SYM_IV_LENGTH              = 12
	THEMIS_AUTH_SYM_AUTH_TAG_LENGTH        = 16
	SOTER_SYM_MAX_KEY_LENGTH               = 128
)

const authSymMessageHeaderFieldsSize = 32 * 4
const AuthSymMessageHeaderSize = authSymMessageHeaderFieldsSize + THEMIS_AUTH_SYM_IV_LENGTH + THEMIS_AUTH_SYM_AUTH_TAG_LENGTH

type AuthTagFieldLength [4]byte
type IV []byte

type AuthSymMessageHeader struct {
	Alg           AuthTagFieldLength
	IVLength      AuthTagFieldLength
	AuthTagLength AuthTagFieldLength
	MessageLength AuthTagFieldLength
	IV            IV
	AuthTag       AuthTag
}

type ThemisError string

func (e ThemisError) Error() string {
	return string(e)
}

var errIVIncorrectLength = ThemisError("incorrect iv format")
var errIncorrectAuthTagLength = ThemisError("incorrect auth tag length")

func NewAuthSymMessageHeader(messageLength uint32, iv IV, authTag AuthTag) (*AuthSymMessageHeader, error) {
	if len(iv) != THEMIS_AUTH_SYM_IV_LENGTH {
		return nil, errIVIncorrectLength
	}
	if len(authTag) != THEMIS_AUTH_SYM_AUTH_TAG_LENGTH {
		return nil, errIncorrectAuthTagLength
	}
	hdr := &AuthSymMessageHeader{}
	binary.LittleEndian.PutUint32(hdr.IVLength[:], THEMIS_AUTH_SYM_IV_LENGTH)
	binary.LittleEndian.PutUint32(hdr.AuthTagLength[:], THEMIS_AUTH_SYM_AUTH_TAG_LENGTH)
	binary.LittleEndian.PutUint32(hdr.Alg[:], THEMIS_AUTH_SYM_ALG)
	binary.LittleEndian.PutUint32(hdr.MessageLength[:], messageLength)
	hdr.IV = iv
	hdr.AuthTag = authTag
	return hdr, nil
}

func (hdr *AuthSymMessageHeader) Marshal() ([]byte, error) {
	output := bytes.NewBuffer(make([]byte, 0, AuthSymMessageHeaderSize))
	binary.Write(output, binary.LittleEndian, hdr.Alg[:])
	binary.Write(output, binary.LittleEndian, hdr.IVLength[:])
	binary.Write(output, binary.LittleEndian, hdr.AuthTagLength[:])
	binary.Write(output, binary.LittleEndian, hdr.MessageLength[:])
	binary.Write(output, binary.LittleEndian, hdr.IV[:])
	binary.Write(output, binary.LittleEndian, hdr.AuthTag[:])
	return output.Bytes(), nil
}

func UnmarshalAuthSymMessageHeader(data []byte) (*AuthSymMessageHeader, error) {
	header := &AuthSymMessageHeader{}
	reader := bytes.NewReader(data)
	if err := binary.Read(reader, binary.LittleEndian, header.Alg[:]); err != nil {
		return nil, err
	}
	if err := binary.Read(reader, binary.LittleEndian, header.IVLength[:]); err != nil {
		return nil, err
	}
	if err := binary.Read(reader, binary.LittleEndian, header.AuthTagLength[:]); err != nil {
		return nil, err
	}
	if err := binary.Read(reader, binary.LittleEndian, header.MessageLength[:]); err != nil {
		return nil, err
	}

	header.IV = make([]byte, int(binary.LittleEndian.Uint32(header.IVLength[:])))
	if err := binary.Read(reader, binary.LittleEndian, header.IV[:]); err != nil {
		return nil, err
	}
	header.AuthTag = make([]byte, int(binary.LittleEndian.Uint32(header.AuthTagLength[:])))
	if err := binary.Read(reader, binary.LittleEndian, header.AuthTag[:]); err != nil {
		return nil, err
	}
	return header, nil
}

type AuthTag []byte
type Context []byte
type EncryptedData []byte

func messageToKDFContext(msg []byte) []byte {
	output := make([]byte, 4)
	binary.LittleEndian.PutUint32(output, uint32(len(msg)))
	return output
}

var ErrInvalidKDFAlgorithm = errors.New("invalid kdf algorithm")

func soterKDF(alg uint32, key, salt []byte) ([]byte, error) {
	switch alg & SOTER_SYM_KDF_MASK {
	case SOTER_SYM_PBKDF2:
		hmac := hmac.New(sha256.New, key)
		return pbkdf2.Key(key, salt, 0, SOTER_SYM_MAX_KEY_LENGTH/8, func() hash.Hash { return hmac }), nil
	case SOTER_SYM_NOKDF:
		return key, nil
	}
	return nil, ErrInvalidKDFAlgorithm

}

func AuthenticatedSymmetricEncryptMessage(key, message []byte, context Context) (EncryptedData, *AuthSymMessageHeader, error) {
	kdfKey := themisKDF(key, THEMIS_SYM_KDF_KEY_LABEL, [][]byte{messageToKDFContext(message), []byte(context)})
	iv := make([]byte, THEMIS_AUTH_SYM_IV_LENGTH)
	if n, err := rand.Read(iv); err != nil {
		return nil, nil, err
	} else if n != THEMIS_AUTH_SYM_IV_LENGTH {
		return nil, nil, errors.New("can't read enough random data for IV")
	}
	derivedKey, err := soterKDF(THEMIS_AUTH_SYM_ALG, kdfKey, nil)
	if err != nil {
		return nil, nil, err
	}
	aes, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, nil, err
	}
	aesGCM, err := cipher.NewGCM(aes)
	if err != nil {
		return nil, nil, err
	}

	ciphertext := aesGCM.Seal(nil, iv, message, context)
	encryptedData := EncryptedData(ciphertext[:len(message)])
	tag := AuthTag(ciphertext[len(message):])
	hdr, err := NewAuthSymMessageHeader(uint32(len(message)), IV(iv), tag)
	if err != nil {
		return nil, nil, err
	}
	return encryptedData, hdr, nil
}

type AuthenticationContext []byte

func CellSeal(key, data []byte, context Context) (EncryptedData, AuthenticationContext, error) {
	encryptedData, authHeader, err := AuthenticatedSymmetricEncryptMessage(key, data, context)
	if err != nil {
		return nil, nil, err
	}
	authContext, err := authHeader.Marshal()
	if err != nil {
		return nil, nil, err
	}
	return encryptedData, authContext, nil
}
