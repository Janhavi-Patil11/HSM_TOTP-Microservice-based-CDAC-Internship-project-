package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"

	"auth-service/database"
	"auth-service/handlers"
	"auth-service/middleware"
)

func main() {

	// ✅ Load .env
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal("❌ Error loading .env file")
	}

	fmt.Println("✅ JWT_SECRET Loaded:", os.Getenv("JWT_SECRET"))

	// ✅ Connect DB
	database.ConnectDB()
	defer database.DB.Close()

	fmt.Println("🚀 Auth Service running on port :9090")

	mux := http.NewServeMux()

	/* ================== PUBLIC ROUTES ================== */

	// Login with email + password (password verification only)
	mux.HandleFunc("/api/login", handlers.Login)

	//  OTP-service calls this after OTP verification (creates login session)
	mux.HandleFunc("/api/login/create-session", handlers.CreateLoginSession)

	//  Final login after OTP verified (generates JWT)
	mux.HandleFunc("/api/login/final", handlers.FinalLogin)

	// Signup → OTP verified → OTP-service creates user
	mux.HandleFunc("/api/signup/create-user", handlers.SignupCreateUser)

	//  Complete profile after signup (NO AUTH - user doesn't have JWT yet)
	mux.HandleFunc("/api/profile/complete", handlers.CompleteProfile)

	//  Forgot password → OTP verified → OTP-service creates reset session
	mux.HandleFunc("/api/forgot/create-session", handlers.CreateResetSession)

	//  Reset password (requires session token)
	mux.HandleFunc("/api/reset-password", handlers.ResetPassword)

	/* ================== EMPLOYEE ROUTES ================== */

	// Get logged-in employee profile
	mux.HandleFunc("/api/profile", middleware.AuthMiddleware(handlers.GetUserProfile))

	// Update employee profile (self update)
	mux.HandleFunc("/api/profile/update", middleware.AuthMiddleware(handlers.UpdateEmployeeProfile))

	/* ================== ADMIN ROUTES ================== */

	// Admin get all employees
	mux.HandleFunc("/api/admin/employees", middleware.AdminMiddleware(handlers.GetAllEmployees))

	// Admin add employee
	mux.HandleFunc("/api/admin/employees/add", middleware.AdminMiddleware(handlers.AddEmployee))

	// Admin update employee
	mux.HandleFunc("/api/admin/employees/update", middleware.AdminMiddleware(handlers.UpdateEmployeeByAdmin))

	// Admin delete employee
	mux.HandleFunc("/api/admin/employees/delete", middleware.AdminMiddleware(handlers.DeleteEmployee))

	/* ================== ENABLE CORS ================== */

	handler := middleware.CORS(mux)

	// Start server
	log.Fatal(http.ListenAndServe(":9090", handler))
}
