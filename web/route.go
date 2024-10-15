package web

import "github.com/gin-gonic/gin"

func RegisterRoutes(e *gin.Engine) {
	RegisterDeviceRoutes(e)
	RegisterAttestationRoutes(e)
	RegisterKvRoutes(e)
}
