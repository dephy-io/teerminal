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
		attestation.GET("/appkey", HandleGetAppDerivedKey)
		attestation.POST("/sign", HandleSignWithAppDerivedKey)
	}
}

type Attestation struct {
	Cert           string `json:"deviceCert"`
	AttestationVer string `json:"attestationVer"`
	TeePlatformVer string `json:"teePlatformVer"`
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
	// Decode hex string to byte array
	data, err := hex.DecodeString(strings.TrimPrefix(req.Data, "0x"))
	if err != nil {
		c.JSON(400, ErrorResponse{Error: constants.MsgErrorFailedDecodeMessage})
	}
	signature, _ := encryption.Sign(data, appKey)
	resp := SignResponse{
		PubKey:    fmt.Sprintf("%x", appPublicKey),
		Signature: fmt.Sprintf("%x", signature),
	}
	c.JSON(200, resp)
}
