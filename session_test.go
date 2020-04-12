package gothemis

import (
	"bytes"
	"fmt"
	"github.com/cossacklabs/themis/gothemis/keys"
	"github.com/cossacklabs/themis/gothemis/session"
	"testing"
)

type themisCb struct{
	p *keys.PublicKey
}

func (t themisCb) GetPublicKeyForId(ss *session.SecureSession, id []byte) *keys.PublicKey {
	return t.p
}

func (t themisCb) StateChanged(ss *session.SecureSession, state int) {
	return
}

type cb struct {
}

func (c cb) Write(date []byte) (int, error) {
	panic("implement me")
}

func (c cb) Read(data []byte) (int, error) {
	panic("implement me")
}

func (c cb) ProtocolStateChanged(event ProtocolEvent) {
	panic("implement me")
}

func (c cb) GetPublicKeyForId(id []byte) (PublicKey, error) {
	panic("implement me")
}

func TestSecureSession_ConnectRequest(t *testing.T) {
	kp, err := NewECKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	themisKp, err := kp.ToThemisKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	kp2, err := NewECKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	themisKp2, err := kp2.ToThemisKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	id := []byte(`test`)
	goSession, err := NewSecureSession(id, kp.Private, kp2.Public, cb{})
	if err != nil {
		t.Fatal(err)
	}
	themisSession, err := session.New(id, themisKp.Private, &themisCb{themisKp2.Public})
	if err != nil {
		t.Fatal(err)
	}
	request, err := goSession.ConnectRequest()
	if err != nil {
		t.Fatal(err)
	}
	themisRequest, err := themisSession.ConnectRequest()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("tag_go: %v\n", request[:12])
	fmt.Printf("tag_th: %v\n", themisRequest[:12])
	fmt.Printf("tag_go: %v\n", request[12:24])
	fmt.Printf("tag_th: %v\n", themisRequest[12:24])
	themisSession2, err := session.New(id, themisKp2.Private, &themisCb{themisKp.Public})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := themisSession2.Unwrap(request); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(request[containerLength:2*containerLength], themisRequest[containerLength:2*containerLength]) {
		t.Fatal(err)
	}

}
