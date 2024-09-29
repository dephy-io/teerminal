package web

import (
	"encoding/hex"
	"fmt"
	"github.com/gin-gonic/gin"
	"strings"
	"teerminal/config"
	"teerminal/constants"
	"teerminal/service/encryption"
)

// @BasePath /api/v1/attestation

func RegisterAttestationRoutes(router *gin.Engine) {
	attestation := router.Group("/api/v1/attestation")
	{
		attestation.GET("/version", HandleGetVersionAttestation)
		attestation.GET("/appkey", HandleGetAppDerivedKey)
		attestation.POST("/sign", HandleSignWithAppDerivedKey)
	}
}

type Attestation struct {
	Cert           string `json:"deviceCert"`
	AttestationVer string `json:"attestationVer"`
	Signature      string `json:"signature"`
}

type ApplicationKey struct {
	Cert   string `json:"appCert"`
	PubKey string `json:"appPubKey"`
}

type SignRequest struct {
	Data string `json:"data"` // Data is the data to be signed
}

type SignResponse struct {
	PubKey    string `json:"pubKey"`
	Signature string `json:"signature"`
}

// HandleGetVersionAttestation godoc
// @Summary Get version attestation for current (simulated) tee version
// @Description Get version attestation for current (simulated) tee version
// @Tags attestation
// @Accept application/json
// @Produce application/json
// @Param attestation query string true "Remote requester's nonce and signature, serialized as hex(64b nonce || 64b pubKey || 65b signature), in which signature is the signature of nonce || pubKey"
// @Success 200 {object} Attestation
// @Failure 400 {object} ErrorResponse
// @Router /api/v1/attestation/version [get]
func HandleGetVersionAttestation(c *gin.Context) {
	// First check if attestation is provided
	attestation := c.Query("attestation")
	if attestation == "" {
		c.JSON(400, ErrorResponse{Error: constants.MsgErrorMissingRemoteAttestation})
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
	// Then sign (nonce || pubKey || version) with the local private key
	version := config.GetConfig().Version
	var signable []byte
	signable = append(signable, nonce...)
	signable = append(signable, pubKey...)
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
		Signature:      fmt.Sprintf("%x", signature),
	})
}

// HandleGetAppDerivedKey godoc
// @Summary Get app derived key for current (simulated) tee version
// @Description Get app derived key for current (simulated) tee version
// @Tags attestation
// @Accept application/json
// @Produce application/json
// @Success 200 {object} ApplicationKey
// @Failure 400 {object} ErrorResponse
// @Router /api/v1/attestation/appkey [get]
func HandleGetAppDerivedKey(c *gin.Context) {
	// First Derive Application Key
	appKey := encryption.DerivePrivateKey(config.GetRootKey(), []byte(config.GetConfig().AppName))
	appPublicKey := encryption.GetPublicKey(appKey)
	// Get Device Cert
	deviceCert := encryption.GetDeviceRootCert()
	// Get Device Root Cert
	deviceRoot := encryption.DerivePrivateKey(config.GetRootKey(), []byte(constants.DeviceRootKey))
	deviceRootCert := encryption.GenerateCert(config.GetRootKey(), []byte(constants.DeviceRootKey))
	applicationCert := encryption.GenerateCert(deviceRoot, []byte(config.GetConfig().AppName))
	var cert []byte
	cert = append(cert, deviceCert...)
	cert = append(cert, deviceRootCert...)
	cert = append(cert, applicationCert...)

	resp := ApplicationKey{
		Cert:   fmt.Sprintf("%x", cert),
		PubKey: fmt.Sprintf("%x", appPublicKey),
	}

	c.JSON(200, resp)
}

// HandleSignWithAppDerivedKey godoc
// @Summary Sign with app derived key for current (simulated) tee version
// @Description Sign with app derived key for current (simulated) tee version
// @Tags attestation
// @Accept application/json
// @Produce application/json
// @Param data body SignRequest true "Data to be signed"
// @Success 200 {object} SignResponse
// @Failure 400 {object} ErrorResponse
// @Router /api/v1/attestation/sign [post]
func HandleSignWithAppDerivedKey(c *gin.Context) {
	appKey := encryption.DerivePrivateKey(config.GetRootKey(), []byte(config.GetConfig().AppName))
	appPublicKey := encryption.GetPublicKey(appKey)
	// Sign the data:
	var req SignRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, ErrorResponse{Error: constants.MsgErrorFailedToBindRequest})
	}
	data := []byte(req.Data)
	signature, _ := encryption.Sign(data, appKey)
	resp := SignResponse{
		PubKey:    fmt.Sprintf("%x", appPublicKey),
		Signature: fmt.Sprintf("%x", signature),
	}
	c.JSON(200, resp)
}
