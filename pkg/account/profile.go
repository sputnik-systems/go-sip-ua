package account

import (
	"fmt"

	"github.com/cloudwebrtc/go-sip-ua/pkg/stack"
	"github.com/ghettovoice/gosip/sip"
	"github.com/ghettovoice/gosip/sip/parser"
	"github.com/google/uuid"
)

//AuthInfo .
type AuthInfo struct {
	AuthUser string
	Realm    string
	Password string
	Ha1      string
}

// Profile .
type Profile struct {
	URI           sip.Uri
	DisplayName   string
	AuthInfo      *AuthInfo
	Expires       uint32
	InstanceID    string
	Routes        []sip.Uri
	ContactURI    sip.Uri
	ContactParams map[string]string
}

// Contact .
func (p *Profile) Contact() *sip.Address {
	var uri sip.Uri
	if p.ContactURI != nil {
		uri = p.ContactURI
	} else {
		uri = p.URI.Clone()
	}

	contact := &sip.Address{
		Uri:    uri,
		Params: sip.NewParams(),
	}
	if p.InstanceID != "nil" {
		contact.Params.Add("+sip.instance", sip.String{Str: p.InstanceID})
	}

	for key, value := range p.ContactParams {
		contact.Params.Add(key, sip.String{Str: value})
	}

	//TODO: Add more necessary parameters.
	//etc: ip:port, transport=udp|tcp, +sip.ice, +sip.instance, +sip.pnsreg,

	return contact
}

//NewProfile .
func NewProfile(
	uri sip.Uri,
	displayName string,
	authInfo *AuthInfo,
	expires uint32,
	routes []sip.Uri,
	stack *stack.SipStack,
) (*Profile, error) {
	p := &Profile{
		URI:         uri,
		DisplayName: displayName,
		AuthInfo:    authInfo,
		Expires:     expires,
		Routes:      routes,
	}
	if stack != nil { // populate the Contact field
		var transport string
		if tp, ok := uri.UriParams().Get("transport"); ok {
			transport = tp.String()
		} else {
			transport = "udp"
		}
		addr := stack.GetNetworkInfo(transport)
		uri, err := parser.ParseUri(fmt.Sprintf("sip:%s@%s;transport=%s", p.URI.User(), addr.Addr(), transport))
		if err == nil {
			p.ContactURI = uri
		} else {
			return nil, fmt.Errorf("error parsing contact URI: %w", err)
		}
	}

	uid, err := uuid.NewUUID()
	if err != nil {
		return nil, fmt.Errorf("could not create UUID: %w", err)
	}
	p.InstanceID = fmt.Sprintf(`"<%s>"`, uid.URN())
	return p, nil
}

//RegisterState .
type RegisterState struct {
	Account    *Profile
	StatusCode sip.StatusCode
	Reason     string
	Expiration uint32
	Response   sip.Response
	UserData   interface{}
}
