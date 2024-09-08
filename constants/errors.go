package constants

import "errors"

const (
	MsgErrorFailedDecodePrivateKey = "failed to decode private key"

	MsgErrorMissingRemoteAttestation         = "missing remote attestation"
	MsgErrorFailedHexDecodeRemoteAttestation = "failed to hex decode remote attestation"
	MsgErrorWrongRemoteAttestationLength     = "wrong remote attestation length"
	MsgErrorWrongRemoteAttestationSignature  = "wrong remote attestation signature"

	MsgErrorFailedToBindRequest = "failed to bind request"

	MsgErrorKeyOrValueNotFound          = "key or value not found"
	MsgErrorFailedProvisionDecoding     = "failed to decode provision"
	MsgErrorInvalidProvisionLength      = "invalid provision length"
	MsgErrorFailedProvisionVerification = "failed to verify provision"
	MsgErrorValueTooLarge               = "value too large"
	MsgErrorKeyExists                   = "key exists"
	MsgErrorKeyDoesNotExist             = "key does not exist"
)

var (
	ErrorFailedDecodePrivateKey = errors.New(MsgErrorFailedDecodePrivateKey)
)
