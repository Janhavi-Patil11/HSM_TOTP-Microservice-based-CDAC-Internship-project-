package main

import (
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"

	"otp-service/handlers"
	"otp-service/middleware"
	"otp-service/store"
)

func main() {

	_ = godotenv.Load()

	// Initialize HSM
	if err := store.InitHSM(); err != nil {
		log.Fatal("HSM Init Failed:", err)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "9091"
	}

	mux := http.NewServeMux()

	// Signup
	mux.HandleFunc("/api/signup/send-otp", handlers.SignupSendOTP)
	mux.HandleFunc("/api/signup/verify-otp", handlers.SignupVerifyOTP)

	// Login
	mux.HandleFunc("/api/login/send-otp", handlers.LoginSendOTP)
	mux.HandleFunc("/api/login/verify-otp", handlers.LoginVerifyOTP)

	// Forgot
	mux.HandleFunc("/api/forgot/send-otp", handlers.SendForgotOTP)
	mux.HandleFunc("/api/forgot/verify-otp", handlers.VerifyForgotOTP)

	// Admin
	mux.HandleFunc("/api/admin/send-otp",
		middleware.JWTMiddleware(handlers.AdminSendOTP))

	mux.HandleFunc("/api/admin/send-otp-multi",
		middleware.JWTMiddleware(handlers.AdminSendOTPMulti))

	mux.HandleFunc("/api/admin/send-notification",
		middleware.JWTMiddleware(handlers.AdminSendNotification))

	mux.HandleFunc("/api/admin/send-notification-multi",
		middleware.JWTMiddleware(handlers.AdminSendNotificationMulti))

	handler := middleware.CORS(mux)

	log.Println("🚀 OTP Service running on :", 9091)
	log.Fatal(http.ListenAndServe(":9091", handler))
}
