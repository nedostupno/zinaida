package utils

import (
	"encoding/json"
	"net/http"
)

func Respond(w http.ResponseWriter, data map[string]interface{}, code int) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(data)
}

func JWTMessage(jwt string, refresh string) map[string]interface{} {
	return map[string]interface{}{"success": true, "access_token": jwt, "refresh_token": refresh}
}
