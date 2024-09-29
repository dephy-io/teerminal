package main

import (
	"github.com/gin-gonic/gin"
	swaggerfiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"teerminal/config"
	"teerminal/docs"
	"teerminal/web"
)

func main() {
	// Load the configuration - todo: add flags to specify the config file
	config.Load("")
	engine := gin.Default()
	docs.SwaggerInfo.BasePath = "/"
	web.RegisterRoutes(engine)
	engine.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerfiles.Handler))
	// Set Listening Port
	engine.Run(":" + config.GetConfig().Port)
	select {}
}
