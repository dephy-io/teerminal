package web

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gin-gonic/gin"
	"strings"
	"teerminal/config"
	"teerminal/constants"
	"teerminal/service/encryption"
)

type Enrollment struct {
	DeviceKey string `json:"deviceKey"`
	Payload   string `json:"deadline"`
	Signature string `json:"signature"`
}

type DeviceKey struct {
	Cert   string `json:"deviceCert"`
	PubKey string `json:"devicePubKey"`
}

func RegisterDeviceRoutes(router *gin.Engine) {
	device := router.Group("/api/v1/device")
	{
		device.POST("/sign", HandleDeviceSign)
		device.GET("/version", HandleGetVersionAttestation)
		device.GET("/key", HandleDeviceKey)
	}
}

// HandleGetVersionAttestation godoc
// @Summary Get version attestation for current (simulated) tee version
// @Description Get version attestation for current (simulated) tee version
// @Tags device
// @Accept application/json
// @Produce application/json
// @Param attestation query string false "Remote requester's nonce and signature, serialized as hex(64b nonce || 64b pubKey || 65b signature), in which signature is the signature of nonce || pubKey, if signature not provided, omit signature"
// @Success 200 {object} Attestation
// @Failure 400 {object} ErrorResponse
// @Router /api/v1/device/version [get]
func HandleGetVersionAttestation(c *gin.Context) {
	// First check if attestation is provided
	attestation := c.Query("attestation")
	if attestation == "" {
		c.JSON(200, Attestation{AttestationVer: config.GetConfig().Version, TeePlatformVer: constants.TeePlatformVersion})
		c.Next()
		return
	}
	// Decode Attestation to bytes
	attestationRawHex := strings.TrimPrefix("0x", attestation)
	attestationRaw, err := hex.DecodeString(attestationRawHex)
	if err != nil {
		c.JSON(400, ErrorResponse{Error: constants.MsgErrorFailedHexDecodeRemoteAttestation})
		c.Next()
		return
	}
	// Check attestationRaw length
	if len(attestationRaw) != 173 {
		c.JSON(400, ErrorResponse{Error: constants.MsgErrorWrongRemoteAttestationLength})
		c.Next()
		return
	}
	// Parse nonce, pubKey and signature
	nonce := attestationRaw[:64]
	pubKey := attestationRaw[64:128]
	signature := attestationRaw[128:]
	// First do the verification of the signature
	if !encryption.VerifySignature(nonce, pubKey, signature) {
		c.JSON(400, ErrorResponse{Error: constants.MsgErrorWrongRemoteAttestationSignature})
		c.Next()
		return
	}
	// Then sign (nonce || pubKey || teePlatformVersion || version) with the local private key
	version := config.GetConfig().Version
	var signable []byte
	signable = append(signable, nonce...)
	signable = append(signable, pubKey...)
	platformVersionBytes := binary.BigEndian.AppendUint64([]byte{}, constants.TeePlatformVersion)
	signable = append(signable, platformVersionBytes...)
	signable = append(signable, []byte(version)...)
	deviceRoot := encryption.DerivePrivateKey(config.GetRootKey(), []byte(constants.DeviceRootKey))
	deviceCert := encryption.GetDeviceRootCert()
	deviceRootCert := encryption.GenerateCert(config.GetRootKey(), []byte(constants.DeviceRootKey))
	signature, _ = encryption.Sign(signable, deviceRoot)
	// Create Concrete Cert
	var cert []byte
	cert = append(cert, deviceCert...)
	cert = append(cert, deviceRootCert...)
	// Return the attestation
	c.JSON(200, Attestation{
		Cert:           fmt.Sprintf("%x", cert),
		AttestationVer: version,
		TeePlatformVer: constants.TeePlatformVersion,
		Signature:      fmt.Sprintf("%x", signature),
	})
}

// HandleDeviceSign godoc
// @Summary Get device enrollment key for current (simulated) tee version
// @Description Get device enrollment key for current (simulated) tee version
// @Description Please see also the DePhy evm sdk.
// @Tags device
// @Accept application/json
// @Param signRequest body SignRequest true "Data to be signed"
// @Produce application/json
// @Success 200 {object} Enrollment
// @Router /api/v1/device/sign [post]
func HandleDeviceSign(c *gin.Context) {
	req := SignRequest{}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, ErrorResponse{Error: constants.MsgErrorFailedToBindRequest})
		c.Next()
		return
	}
	data, err := hex.DecodeString(strings.TrimPrefix(req.Data, "0x"))
	if err != nil {
		c.JSON(400, ErrorResponse{Error: constants.MsgErrorFailedDecodeMessage})
	}
	// eth keccak256 hash of the deadline
	msgHash := crypto.Keccak256(data)
	msgSignPayload := append([]byte(constants.DeviceEnrollmentKey), msgHash...)
	// Sign the payload with the root key
	deviceRoot := encryption.DerivePrivateKey(config.GetRootKey(), []byte(constants.DeviceRootKey))
	deviceRootPublic := encryption.GetPublicKey(deviceRoot)
	signature, _ := encryption.Sign(deviceRoot, msgSignPayload)
	// Return the enrollment key and deadline as hex
	c.JSON(200, Enrollment{
		DeviceKey: fmt.Sprintf("%x", deviceRootPublic),
		Payload:   req.Data,
		Signature: fmt.Sprintf("%x", signature),
	})

}

// HandleDeviceKey godoc
// @Summary Get device key for current (simulated) tee version
// @Description Get device key for current (simulated) tee version
// @Tags device
// @Accept application/json
// @Produce application/json
// @Success 200 {object} DeviceKey
// @Router /api/v1/device/key [get]
func HandleDeviceKey(c *gin.Context) { // Get Device Cert
	deviceCert := encryption.GetDeviceRootCert()
	// Get Device Root Cert
	deviceRoot := encryption.DerivePrivateKey(config.GetRootKey(), []byte(constants.DeviceRootKey))
	deviceRootCert := encryption.GenerateCert(config.GetRootKey(), []byte(constants.DeviceRootKey))
	deviceCertPubKey := encryption.GetPublicKey(deviceRoot)
	var cert []byte
	cert = append(cert, deviceCert...)
	cert = append(cert, deviceRootCert...)

	resp := ApplicationKey{
		Cert:   fmt.Sprintf("%x", cert),
		PubKey: fmt.Sprintf("%x", deviceCertPubKey),
	}

	c.JSON(200, resp)
}
