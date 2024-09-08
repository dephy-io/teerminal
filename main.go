package main

import (
	"github.com/gin-gonic/gin"
	"teerminal/config"
)

func main() {
	// Load the configuration - todo: add flags to specify the config file
	config.Load("")
	engine := gin.Default()
	// Set Listening Port
	engine.Run(":" + config.GetConfig().Port)
	select {}
}
