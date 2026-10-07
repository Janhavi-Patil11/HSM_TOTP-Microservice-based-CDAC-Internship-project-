package middleware

import (
	"net/http"
	"strings"

	"otp-service/utils"
)

func JWTMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Missing token", 401)
			return
		}

		tokenString := strings.Replace(authHeader, "Bearer ", "", 1)

		claims, err := utils.VerifyJWT(tokenString)
		if err != nil {
			http.Error(w, "Invalid token", 401)
			return
		}

		r.Header.Set("X-User-Email", claims.Email)
		r.Header.Set("X-User-Role", claims.Role)

		next(w, r)
	}
}
