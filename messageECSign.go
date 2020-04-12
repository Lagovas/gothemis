package gothemis

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"math/big"
)

const (
	THEMIS_SECURE_MESSAGE = 0x26040000

	THEMIS_SECURE_MESSAGE_SIGNED     = (THEMIS_SECURE_MESSAGE ^ 0x00002600)
	THEMIS_SECURE_MESSAGE_RSA_SIGNED = (THEMIS_SECURE_MESSAGE_SIGNED ^ 0x00000010)
	THEMIS_SECURE_MESSAGE_EC_SIGNED  = (THEMIS_SECURE_MESSAGE_SIGNED ^ 0x00000020)
)

type secureMessageHeader struct {
	operationType uint32
	length        uint32
}

type signedMessageHeader struct {
	messageHeader   secureMessageHeader
	signatureLength uint32
}

const (
	signedMessageStaticOverhead = 12 // sizeof(messageHeader) + sizeof(signedMessageHeader)
)

func signECDSA(data []byte, private *ecdsa.PrivateKey)([]byte, error){
	mac := sha256.Sum256(data)
	signature, err := private.Sign(rand.Reader, mac[:], nil)
	if err != nil {
		return nil, err
	}
	return signature, nil
}

func Sign(data []byte, privateKey *PrivateECKey) ([]byte, error) {
	signature, err := signECDSA(data, privateKey.private)
	if err != nil {
		return nil, err
	}
	output := make([]byte, len(data)+len(signature)+signedMessageStaticOverhead)
	binary.LittleEndian.PutUint32(output[:4], uint32(THEMIS_SECURE_MESSAGE_EC_SIGNED))
	binary.LittleEndian.PutUint32(output[4:8], uint32(len(data)))
	binary.LittleEndian.PutUint32(output[8:12], uint32(len(signature)))
	writer := bytes.NewBuffer(output[:signedMessageStaticOverhead])
	binary.Write(writer, binary.LittleEndian, data)
	binary.Write(writer, binary.LittleEndian, signature)
	return output, nil
}

var ErrVerify = errors.New("Failed to verify message")

func validateSecureMessageType(messageType uint32) bool {
	switch messageType {
	case uint32(THEMIS_SECURE_MESSAGE_EC_SIGNED):
		return true
	}
	return false
}

type signatureParams struct {
	R, S *big.Int
}

func parseGoDEREncodedECDSASignature(signature []byte, params *signatureParams) error {
	_, err := asn1.Unmarshal(signature, params)
	return err
}

func Verify(data []byte, public *PublicECKey) ([]byte, error) {
	if len(data) < signedMessageStaticOverhead {
		return nil, ErrVerify
	}
	messageType := binary.LittleEndian.Uint32(data[:4])
	if !validateSecureMessageType(messageType) {
		return nil, ErrVerify
	}
	dataLength := binary.LittleEndian.Uint32(data[4:8])
	signatureLength := binary.LittleEndian.Uint32(data[8:12])
	if int(dataLength+signatureLength+signedMessageStaticOverhead) != len(data) {
		return nil, ErrVerify
	}
	signature := data[signedMessageStaticOverhead+dataLength:]
	sigParams := &signatureParams{R: new(big.Int), S: new(big.Int)}
	if err := parseGoDEREncodedECDSASignature(signature, sigParams); err != nil {
		return nil, ErrVerify
	}
	sourceMessage := data[signedMessageStaticOverhead : signedMessageStaticOverhead+dataLength]
	digest := sha256.Sum256(sourceMessage)
	verify := ecdsa.Verify(public.Public(), digest[:], sigParams.R, sigParams.S)
	if !verify {
		return nil, ErrVerify
	}
	return sourceMessage, nil
}
