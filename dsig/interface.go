package dsig

import (
	"github.com/5teven/xmlsec/clib"
	"github.com/5teven/xmlsec/crypto"
	"github.com/lestrrat-go/libxml2/types"
)

type TransformID clib.TransformID

var (
	ExclC14N  = TransformID(clib.ExclC14N)
	InclC14N  = TransformID(clib.InclC14N)
	Enveloped = TransformID(clib.Enveloped)
	Sha1      = TransformID(clib.Sha1)
	RsaSha1   = TransformID(clib.RsaSha1)
	Gost2001  = TransformID(clib.Gost2001)
)

type Ctx struct {
	ptr uintptr // *C.xmlSecDSigCtx
}

type Signature struct {
	keyinfo    types.Node
	refnode    types.Node
	signmethod TransformID
	signnode   types.Node
}

// SignatureVerify is a convenience wrapper for things that can verify
// XML strings
type SignatureVerify struct {
	key *crypto.Key
}
