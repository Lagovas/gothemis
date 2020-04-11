package gothemis

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"math/big"
)

type secureMessage struct {
	privateKey *PrivateECKey
	publicKey  *PublicECKey
}

var ErrKeysUseDifferentCurves = errors.New("private and public keys use different curves")

const (
	themisSecureMessage            = 0x26040000
	ThemisSecureMessageEncrypted   = themisSecureMessage ^ 0x00002700
	ThemisSecureMessageECEncrypted = ThemisSecureMessageEncrypted ^ 0x00000020
	themisSecureMessageHeaderSize  = 8
)

func IsSecureMessageEncrypted(tag uint32) bool {
	return tag&0xffffff00 == ThemisSecureMessageEncrypted
}

type SecureMessageData struct {
	messageType [4]byte
	length      [4]byte
	data        []byte
}

var ErrDataTooLongForUint32 = errors.New("data length can't be stored in uint32 field")

func NewSecureMessageECEncrypted(data []byte) (*SecureMessageData, error) {
	smd := &SecureMessageData{}
	if len(data) > math.MaxUint32 {
		return nil, ErrDataTooLongForUint32
	}
	binary.LittleEndian.PutUint32(smd.messageType[:], ThemisSecureMessageECEncrypted)
	binary.LittleEndian.PutUint32(smd.length[:], uint32(len(data)+themisSecureMessageHeaderSize))
	smd.data = data
	return smd, nil
}
func SecureMessageDataFromMessage(data []byte) (*SecureMessageData, error) {
	if len(data) < themisSecureMessageHeaderSize {
		return nil, ErrInvalidMessageLength
	}
	smd := &SecureMessageData{
		data: data[8:],
	}
	copy(smd.messageType[:], data[:4])
	copy(smd.length[:], data[4:8])
	if len(data) != int(binary.LittleEndian.Uint32(smd.length[:])) {
		return nil, ErrInvalidMessageLength
	}

	return smd, nil
}

func (smd *SecureMessageData) Marshal() ([]byte, error) {
	length := int(binary.LittleEndian.Uint32(smd.length[:]))
	output := bytes.NewBuffer(make([]byte, 0, 8+length))
	binary.Write(output, binary.LittleEndian, smd.messageType)
	binary.Write(output, binary.LittleEndian, smd.length)
	binary.Write(output, binary.LittleEndian, smd.data)
	return output.Bytes(), nil
}

func (smd *SecureMessageData) MessageSize() uint32 {
	return binary.LittleEndian.Uint32(smd.length[:])
}

func NewSecureMessage(private *PrivateECKey, public *PublicECKey) (*secureMessage, error) {
	if TagToCurve(private.tag[:]) != TagToCurve(public.tag[:]) {
		return nil, ErrKeysUseDifferentCurves
	}
	return &secureMessage{private, public}, nil
}

func (smessage *secureMessage) Wrap(data []byte) ([]byte, error) {
	curve := TagToCurve(smessage.privateKey.tag[:])
	d := smessage.privateKey.private.D.Bytes()
	defer Zeroize(d)
	x, _ := curve.ScalarMult(smessage.publicKey.x, smessage.publicKey.y, d)
	sharedKey := alignPointInBytes(curve.Params().BitSize/8, x)
	// zeroize temp key
	x.Set(new(big.Int))
	encrypted, err := CellSealEncrypt(sharedKey, data, nil)
	if err != nil {
		return nil, ThemisError(err.Error())
	}
	Zeroize(sharedKey)
	smd, err := NewSecureMessageECEncrypted(encrypted)
	if err != nil {
		return nil, ThemisError(err.Error())
	}
	return smd.Marshal()
}

var ErrInvalidMessageLength = errors.New("message has incorrect length")

func (smessage *secureMessage) Unwrap(data []byte) ([]byte, error) {
	messageData, err := SecureMessageDataFromMessage(data)
	if err != nil {
		return nil, err
	}
	if messageData.MessageSize() != uint32(len(data)) {
		return nil, ErrInvalidMessageLength
	}
	curve := TagToCurve(smessage.privateKey.tag[:])
	d := smessage.privateKey.private.D.Bytes()
	defer Zeroize(d)
	x, _ := curve.ScalarMult(smessage.publicKey.x, smessage.publicKey.y, d)

	sharedKey := alignPointInBytes(curve.Params().BitSize/8, x)
	// zeroize temp key
	x.Set(new(big.Int))

	decrypted, err := CellSealDecrypt(sharedKey, messageData.data, nil)
	if err != nil {
		return nil, ThemisError(err.Error())
	}
	Zeroize(sharedKey)
	return decrypted, nil
}
