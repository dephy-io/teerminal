package web

import "github.com/gin-gonic/gin"

func RegisterRoutes(e *gin.Engine) {
	RegisterAttestationRoutes(e)
	RegisterKvRoutes(e)
}
