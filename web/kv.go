package web

import (
	"encoding/hex"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gin-gonic/gin"
	"strings"
	"teerminal/config"
	"teerminal/constants"
	"teerminal/service/encryption"
	"teerminal/service/kv"
)

// @BasePath /api/v1/kv

func RegisterKvRoutes(r *gin.Engine) {
	kvGroup := r.Group("/api/v1/kv")
	{
		kvGroup.POST("/write", HandleWriteKv)
		kvGroup.GET("/read", HandleReadKv)
		kvGroup.POST("/delete", HandleDeleteKv)
		kvGroup.GET("/quota", HandleQuota)
	}
}

type WriteKvRequest struct {
	Key       string `json:"key"`
	Value     string `json:"value"`
	Provision string `json:"provision"`
	Protected string `json:"protected"`
	Overwrite bool   `json:"overwrite"`
}

type DeleteKvRequest struct {
	Key string `json:"key"`
}

type WriteKvResponse struct {
	Success bool `json:"success"`
}

type ReadKvResponse struct {
	Present     bool   `json:"present"`
	Value       string `json:"value"`
	Provisioned bool   `json:"provisioned"`
	Protected   bool   `json:"protected"`
	Provisioner string `json:"provisioner,omitempty"`
	Protector   string `json:"protector,omitempty"`
}

type DeleteKvResponse struct {
	Success bool `json:"success"`
}

type QuotaResponse struct {
	Used  int `json:"used"`
	Quota int `json:"quota"`
}

// HandleWriteKv godoc
// @Summary Write a key-value pair
// @Description Write a key-value pair, If Provision is provided, the remote provision information will be added, and only the provisioner can write it, If Protected is provided, the target key will be protected, and only the protector can read it.
// @Tags kv
// @Accept json
// @Produce json
// @Param key json string true "Key"
// @Param value json string true "Value"
// @Param provision string false "Remote Provision Signature, Should be pubKey(64b) || sig(appKey(64byte) || keccak256(key) ||  keccak256(value)))"
// @Param protected string false "Protect Target Key"
// @Success 200 {object} WriteKvResponse
// @Failure 400 {object} ErrorResponse
// @Router /write [post]
func HandleWriteKv(c *gin.Context) {
	var req WriteKvRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, ErrorResponse{Error: err.Error()})
		c.Next()
		return
	}
	// Check key & value status
	if req.Key == "" || req.Value == "" {
		c.JSON(400, ErrorResponse{Error: constants.MsgErrorKeyOrValueNotFound})
		c.Next()
		return
	}
	// Check provision & protected
	var provisioner string
	if req.Provision != "" {
		// Go Check Provision
		// First Try To Parse Hex
		payload, err := hex.DecodeString(strings.TrimPrefix(req.Provision, "0x"))
		if err != nil {
			c.JSON(400, ErrorResponse{Error: constants.MsgErrorFailedProvisionDecoding})
			c.Next()
			return
		}
		// Check Length
		if len(payload) != 128 {
			c.JSON(400, ErrorResponse{Error: constants.MsgErrorInvalidProvisionLength})
			c.Next()
			return
		}
		// Check Signature
		/// First Extract PubKey & Sig
		pubKey := payload[:64]
		sig := payload[64:]
		/// Then create the signed message
		appKey := encryption.DerivePrivateKey(config.GetRootKey(), []byte(config.GetConfig().AppName))
		appPublicKey := encryption.GetPublicKey(appKey)
		keyHash := crypto.Keccak256([]byte(req.Key))
		valueHash := crypto.Keccak256([]byte(req.Value))
		message := append(appPublicKey, keyHash...)
		message = append(message, valueHash...)
		/// Then Verify
		if !encryption.VerifySignature(pubKey, message, sig) {
			c.JSON(400, ErrorResponse{Error: constants.MsgErrorFailedProvisionVerification})
			c.Next()
			return
		}
		provisioner = hex.EncodeToString(pubKey)
	}
	// Check value length
	if len(req.Value) > constants.MaxKvLength {
		c.JSON(400, ErrorResponse{Error: constants.MsgErrorValueTooLarge})
		c.Next()
		return
	}
	// Check if the key exists
	if kv.Exists(req.Key) && !req.Overwrite {
		c.JSON(400, ErrorResponse{Error: constants.MsgErrorKeyExists})
		c.Next()
		return
	}
	valStruct := kv.Entry{
		Key:         req.Key,
		Value:       req.Value,
		Provisioner: provisioner,
		Protector:   req.Protected,
	}
	kv.Store(valStruct)
	c.JSON(200, WriteKvResponse{Success: true})
	c.Next()
}

// HandleReadKv godoc
// @Summary Read a key-value pair
// @Description Read a key-value pair, If the target key is protected, the protector must be provided.
// @Tags kv
// @Accept json
// @Produce json
// @Param key query string true "Key"
// @Success 200 {object} ReadKvResponse
// @Failure 400 {object} ErrorResponse
// @Router /read [get]
func HandleReadKv(c *gin.Context) {
	key := c.Query("key")
	if key == "" {
		c.JSON(400, ErrorResponse{Error: constants.MsgErrorKeyOrValueNotFound})
		c.Next()
		return
	}
	entry, exists := kv.Load(key)
	if !exists {
		c.JSON(400, ErrorResponse{Error: constants.MsgErrorKeyExists})
		c.Next()
		return
	}
	// Todo: encrypt protected value using protector's public key
	c.JSON(200, ReadKvResponse{
		Present:     true,
		Value:       entry.Value,
		Provisioned: entry.Provisioner != "",
		Protected:   entry.Protector != "",
		Provisioner: entry.Provisioner,
		Protector:   entry.Protector,
	})
	c.Next()
}

// HandleDeleteKv godoc
// @Summary Delete a key-value pair
// @Description Delete a key-value pair
// @Tags kv
// @Accept json
// @Produce json
// @Param key query string true "Key"
// @Success 200 {object} WriteKvResponse
// @Failure 400 {object} ErrorResponse
// @Router /delete [delete]
func HandleDeleteKv(c *gin.Context) {
	req := DeleteKvRequest{}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, ErrorResponse{Error: err.Error()})
	}
	if req.Key == "" {
		c.JSON(400, ErrorResponse{Error: constants.MsgErrorKeyOrValueNotFound})
		c.Next()
		return
	}
	if !kv.Exists(req.Key) {
		c.JSON(400, ErrorResponse{Error: constants.MsgErrorKeyDoesNotExist})
		c.Next()
		return
	}
	kv.Delete(req.Key)
	c.JSON(200, DeleteKvResponse{Success: true})
}

// HandleQuota godoc
// @Summary Get the quota of the current application
// @Description Get the quota of the current application, return the number of keys that can be written
// @Tags kv
// @Accept none
// @Produce json
// @Success 200 {object} QuotaResponse
// @Failure 400 {object} ErrorResponse
// @Router /quota [get]
func HandleQuota(c *gin.Context) {
	used := kv.Length()
	quota := constants.MaxKvEntries
	c.JSON(200, QuotaResponse{Used: used, Quota: quota})
}
