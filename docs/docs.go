// Package docs Code generated by swaggo/swag. DO NOT EDIT
package docs

import "github.com/swaggo/swag"

const docTemplate = `{
    "schemes": {{ marshal .Schemes }},
    "swagger": "2.0",
    "info": {
        "description": "{{escape .Description}}",
        "title": "{{.Title}}",
        "contact": {},
        "version": "{{.Version}}"
    },
    "host": "{{.Host}}",
    "basePath": "{{.BasePath}}",
    "paths": {
        "/api/v1/attestation/appkey": {
            "get": {
                "description": "Get app derived key for current (simulated) tee version",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "attestation"
                ],
                "summary": "Get app derived key for current (simulated) tee version",
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/web.ApplicationKey"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/web.ErrorResponse"
                        }
                    }
                }
            }
        },
        "/api/v1/attestation/sign": {
            "get": {
                "description": "Sign with app derived key for current (simulated) tee version",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "attestation"
                ],
                "summary": "Sign with app derived key for current (simulated) tee version",
                "parameters": [
                    {
                        "description": "Data to be signed",
                        "name": "data",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "type": "string"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/web.SignResponse"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/web.ErrorResponse"
                        }
                    }
                }
            }
        },
        "/api/v1/attestation/version": {
            "get": {
                "description": "Get version attestation for current (simulated) tee version",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "attestation"
                ],
                "summary": "Get version attestation for current (simulated) tee version",
                "parameters": [
                    {
                        "type": "string",
                        "description": "Remote requester's nonce and signature, serialized as hex(64b nonce || 64b pubKey || 65b signature), in which signature is the signature of nonce || pubKey",
                        "name": "attestation",
                        "in": "query",
                        "required": true
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/web.Attestation"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/web.ErrorResponse"
                        }
                    }
                }
            }
        },
        "/delete": {
            "delete": {
                "description": "Delete a key-value pair",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "kv"
                ],
                "summary": "Delete a key-value pair",
                "parameters": [
                    {
                        "type": "string",
                        "description": "Key",
                        "name": "key",
                        "in": "query",
                        "required": true
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/web.WriteKvResponse"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/web.ErrorResponse"
                        }
                    }
                }
            }
        },
        "/quota": {
            "get": {
                "description": "Get the quota of the current application, return the number of keys that can be written",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "kv"
                ],
                "summary": "Get the quota of the current application",
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/web.QuotaResponse"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/web.ErrorResponse"
                        }
                    }
                }
            }
        },
        "/read": {
            "get": {
                "description": "Read a key-value pair, If the target key is protected, the protector must be provided.",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "kv"
                ],
                "summary": "Read a key-value pair",
                "parameters": [
                    {
                        "type": "string",
                        "description": "Key",
                        "name": "key",
                        "in": "query",
                        "required": true
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/web.ReadKvResponse"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/web.ErrorResponse"
                        }
                    }
                }
            }
        },
        "/write": {
            "post": {
                "description": "Write a key-value pair, If Provision is provided, the remote provision information will be added, and only the provisioner can write it, If Protected is provided, the target key will be protected, and only the protector can read it.",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "kv"
                ],
                "summary": "Write a key-value pair",
                "parameters": [
                    {
                        "description": "Key",
                        "name": "key",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "type": "string"
                        }
                    },
                    {
                        "description": "Value",
                        "name": "value",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "type": "string"
                        }
                    },
                    {
                        "description": "Remote Provision Signature, Should be pubKey(64b) || sig(appKey(64byte) || keccak256(key) ||  keccak256(value)))",
                        "name": "provision",
                        "in": "body",
                        "schema": {
                            "type": "string"
                        }
                    },
                    {
                        "description": "Protect Target Key",
                        "name": "protected",
                        "in": "body",
                        "schema": {
                            "type": "string"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/web.WriteKvResponse"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/web.ErrorResponse"
                        }
                    }
                }
            }
        }
    },
    "definitions": {
        "web.ApplicationKey": {
            "type": "object",
            "properties": {
                "appCert": {
                    "type": "string"
                },
                "appPubKey": {
                    "type": "string"
                }
            }
        },
        "web.Attestation": {
            "type": "object",
            "properties": {
                "attestationVer": {
                    "type": "string"
                },
                "deviceCert": {
                    "type": "string"
                },
                "signature": {
                    "type": "string"
                }
            }
        },
        "web.ErrorResponse": {
            "type": "object",
            "properties": {
                "error": {
                    "type": "string"
                }
            }
        },
        "web.QuotaResponse": {
            "type": "object",
            "properties": {
                "quota": {
                    "type": "integer"
                },
                "used": {
                    "type": "integer"
                }
            }
        },
        "web.ReadKvResponse": {
            "type": "object",
            "properties": {
                "present": {
                    "type": "boolean"
                },
                "protected": {
                    "type": "boolean"
                },
                "protector": {
                    "type": "string"
                },
                "provisioned": {
                    "type": "boolean"
                },
                "provisioner": {
                    "type": "string"
                },
                "value": {
                    "type": "string"
                }
            }
        },
        "web.SignResponse": {
            "type": "object",
            "properties": {
                "pubKey": {
                    "type": "string"
                },
                "signature": {
                    "type": "string"
                }
            }
        },
        "web.WriteKvResponse": {
            "type": "object",
            "properties": {
                "success": {
                    "type": "boolean"
                }
            }
        }
    }
}`

// SwaggerInfo holds exported Swagger Info so clients can modify it
var SwaggerInfo = &swag.Spec{
	Version:          "",
	Host:             "",
	BasePath:         "",
	Schemes:          []string{},
	Title:            "",
	Description:      "",
	InfoInstanceName: "swagger",
	SwaggerTemplate:  docTemplate,
	LeftDelim:        "{{",
	RightDelim:       "}}",
}

func init() {
	swag.Register(SwaggerInfo.InstanceName(), SwaggerInfo)
}