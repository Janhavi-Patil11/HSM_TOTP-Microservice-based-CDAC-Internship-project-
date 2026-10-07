package handlers

import (
	"encoding/json"
	"net/http"

	"otp-service/services"
	"otp-service/utils"
)

type ForgotSendRequest struct {
	Email string `json:"email"`
}

type ForgotVerifyRequest struct {
	Email string `json:"email"`
	OTPId string `json:"otp_id"`
	OTP   string `json:"otp"`
}

/* ================= SEND FORGOT OTP ================= */

func SendForgotOTP(w http.ResponseWriter, r *http.Request) {

	var req ForgotSendRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.JSON(w, 400, map[string]string{"error": "Invalid request body"})
		return
	}

	if !utils.IsValidEmail(req.Email) {
		utils.JSON(w, 400, map[string]string{"error": "Invalid email"})
		return
	}

	// 🔥 FIX: Updated to handle new 3-return-value signature
	otpID, remainingSeconds, err := services.GenerateAndSendOTP(req.Email)
	if err != nil {
		utils.JSON(w, 500, map[string]string{"error": err.Error()})
		return
	}

	utils.JSON(w, 200, map[string]interface{}{
		"message":           "Forgot OTP sent",
		"otp_id":            otpID,
		"remaining_seconds": remainingSeconds,
	})
}

/* ================= VERIFY FORGOT OTP ================= */

func VerifyForgotOTP(w http.ResponseWriter, r *http.Request) {

	var req ForgotVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.JSON(w, 400, map[string]string{"error": "Invalid request body"})
		return
	}

	if req.Email == "" || req.OTPId == "" || req.OTP == "" {
		utils.JSON(w, 400, map[string]string{"error": "Email, OTP ID and OTP required"})
		return
	}

	if !utils.IsValidOTP(req.OTP) {
		utils.JSON(w, 400, map[string]string{"error": "OTP must be 6 digits"})
		return
	}

	ok, err := services.VerifyStoredOTP(req.OTPId, req.OTP)
	if err != nil {
		utils.JSON(w, 400, map[string]string{"error": err.Error()})
		return
	}

	if !ok {
		utils.JSON(w, 401, map[string]string{"error": "Invalid OTP"})
		return
	}

	// 🔥 Create reset session in auth-service
	sessionToken, err := services.CallAuthCreateResetSession(req.Email, req.OTPId)
	if err != nil {
		utils.JSON(w, 500, map[string]string{"error": err.Error()})
		return
	}

	utils.JSON(w, 200, map[string]string{
		"message":       "OTP verified",
		"session_token": sessionToken,
	})
}
