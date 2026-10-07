package handlers

import (
	"encoding/json"
	"net/http"

	"otp-service/services"
	"otp-service/utils"
)

/* ================= REQUEST STRUCTS ================= */

type LoginSendRequest struct {
	Email string `json:"email"`
}

type LoginVerifyRequest struct {
	Email string `json:"email"`
	OTPId string `json:"otp_id"`
	OTP   string `json:"otp"`
}

/* ================= LOGIN SEND OTP ================= */
func LoginSendOTP(w http.ResponseWriter, r *http.Request) {

	var req LoginSendRequest

	// Decode request body
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.JSON(w, 400, map[string]string{"error": "Invalid request body"})
		return
	}

	// Validate email
	if !utils.IsValidEmail(req.Email) {
		utils.JSON(w, 400, map[string]string{"error": "Invalid email format"})
		return
	}

	// 🔥 FIX: GenerateAndSendOTP now returns remaining_seconds too
	otpID, remainingSeconds, err := services.GenerateAndSendOTP(req.Email)
	if err != nil {
		utils.JSON(w, 500, map[string]string{"error": err.Error()})
		return
	}

	// 🔥 FIX: Include remaining_seconds in the response so the frontend
	// countdown starts from the correct value (not always 60)
	utils.JSON(w, 200, map[string]interface{}{
		"message":           "Login OTP sent successfully",
		"otp_id":            otpID,
		"remaining_seconds": remainingSeconds,
	})
}

/* ================= LOGIN VERIFY OTP ================= */

func LoginVerifyOTP(w http.ResponseWriter, r *http.Request) {

	var req LoginVerifyRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.JSON(w, 400, map[string]string{"error": "Invalid request body"})
		return
	}

	// Validate inputs
	if !utils.IsValidEmail(req.Email) {
		utils.JSON(w, 400, map[string]string{"error": "Invalid email format"})
		return
	}

	if req.OTPId == "" || req.OTP == "" {
		utils.JSON(w, 400, map[string]string{"error": "OTP ID and OTP are required"})
		return
	}

	if !utils.IsValidOTP(req.OTP) {
		utils.JSON(w, 400, map[string]string{"error": "OTP must be 6 digits"})
		return
	}

	// Verify OTP using HSM
	ok, err := services.VerifyStoredOTP(req.OTPId, req.OTP)
	if err != nil {
		utils.JSON(w, 500, map[string]string{"error": err.Error()})
		return
	}

	if !ok {
		utils.JSON(w, 401, map[string]string{"error": "Invalid or expired OTP"})
		return
	}

	// 🔥 Create Login Session in Auth Service
	sessionToken, err := services.CallAuthCreateLoginSession(req.Email, req.OTPId)
	if err != nil {
		utils.JSON(w, 500, map[string]string{"error": "Failed to create login session"})
		return
	}

	utils.JSON(w, 200, map[string]string{
		"message":       "Login OTP verified",
		"session_token": sessionToken,
	})
}
