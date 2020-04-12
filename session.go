package gothemis

import (
	"encoding/binary"
	"errors"
)

type SecureSession interface {
	ConnectRequest() ([]byte, error)
}

type PublicKey []byte
type ProtocolEvent int
type Callback interface {
	Write(date []byte) (int, error)
	Read(data []byte) (int, error)
	ProtocolStateChanged(event ProtocolEvent)
	GetPublicKeyForId(id []byte) (PublicKey, error)
}

var (
	ErrEmptyCallback   = errors.New("secure session callback is nil")
	ErrEmptyPrivateKey = errors.New("empty private key")
)

const (
	// id tag
	THEMIS_SESSION_ID_TAG = "TSID"
	// protocol tag
	THEMIS_SESSION_PROTO_TAG = "TSPM"
)

func validateCallback(c Callback) error {
	if c == nil {
		return ErrEmptyCallback
	}
	return nil
}

type secureSession struct {
	id          []byte
	ecdhKeypair *KeyPair
	signKey     *PrivateECKey
	peerPublicKey *PublicECKey
	callback    Callback
}

func newSecureSession(id []byte, signKey *PrivateECKey, publicKey *PublicECKey, callback Callback) (*secureSession, error) {
	if signKey == nil {
		return nil, ErrEmptyPrivateKey
	}
	if err := validateCallback(callback); err != nil {
		return nil, err
	}
	kp, err := NewECKeyPair()
	if err != nil {
		return nil, err
	}
	return &secureSession{id: id, ecdhKeypair: kp, signKey: signKey, callback: callback, peerPublicKey: publicKey}, nil
}

const (
	soterTagLength  = 4
	containerLength = soterTagLength + 4 + 4 // tag[soterTagLength] + size[uint32] + crc[uint32]
)

var ErrInvalidSoterContainerLength = errors.New("small slice for soter container")
var ErrInvalidBufferForCRC = errors.New("buffer has incorrect size according to soter header")

// soterContainer has next structure:
// {
//	tag  [soterTagLength]byte
//	size uint32
//	crc  uint32
// }
type soterContainer []byte

func (container soterContainer) calculateCRC(buf []byte) error {
	if len(container) < containerLength {
		return ErrInvalidSoterContainerLength
	}
	size := binary.BigEndian.Uint32(container[4:8])
	if len(buf) < int(size){
		return ErrInvalidBufferForCRC
	}
	crcHash := NewCRC32()
	crcHash.Write(buf[:size])
	binary.LittleEndian.PutUint32(container[8:12], crcHash.Sum32())
	return nil
}

func (container soterContainer) setSizeToContainer(size int) error {
	if len(container) < containerLength {
		return ErrInvalidSoterContainerLength
	}
	binary.BigEndian.PutUint32(container[4:8], uint32(size+containerLength))
	return nil
}

func (container soterContainer) setTag(tag []byte) error {
	if len(container) < containerLength {
		return ErrInvalidSoterContainerLength
	}
	copy(container[:4], tag)
	return nil
}

func (session *secureSession) ConnectRequest() ([]byte, error) {
	pubkeyBytes, err := session.peerPublicKey.Marshal()
	if err != nil {
		return nil, err
	}
	signature, err := signECDSA(pubkeyBytes, session.signKey.private)
	if err != nil {
		return nil, err
	}

	//length := 2*containerLength + len(session.id)
	totalLength := 2*containerLength + len(session.id) + len(pubkeyBytes) + len(signature)
	output := make([]byte, totalLength)

	// save total metadata and first soter container header
	container := soterContainer(output[:containerLength])
	if err := container.setTag([]byte(THEMIS_SESSION_PROTO_TAG)); err != nil {
		return nil, err
	}
	if err := container.setSizeToContainer(totalLength - containerLength); err != nil {
		return nil, err
	}

	// save id length as second soter container
	container = soterContainer(output[containerLength:2*containerLength])
	if err := container.setTag([]byte(THEMIS_SESSION_ID_TAG)); err != nil {
		return nil, err
	}
	if err := container.setSizeToContainer(len(session.id)); err != nil {
		return nil, err
	}

	// save id after two containers
	index := 2 * containerLength
	copy(output[index:index+len(session.id)], session.id)

	// calculate crc for header related with id
	if err := container.calculateCRC(output[containerLength:]); err != nil {
		return nil, err
	}

	// save public key after id
	index += len(session.id)
	copy(output[index:index+len(pubkeyBytes)], pubkeyBytes)
	// save signature of public key after public key
	index += len(pubkeyBytes)
	copy(output[index:], signature)
	// calculate total crc
	container = soterContainer(output[:containerLength])
	if err := container.calculateCRC(output); err != nil {
		return nil, err
	}

	return output, nil
}

func NewSecureSession(id []byte, signatureKey *PrivateECKey, publicKey *PublicECKey, callback Callback) (SecureSession, error) {
	s, err := newSecureSession(id, signatureKey, publicKey, callback)
	if err != nil {
		return nil, err
	}

	return s, nil
}
