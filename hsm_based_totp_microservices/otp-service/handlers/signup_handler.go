package handlers

import (
	"encoding/json"
	"net/http"

	"otp-service/services"
	"otp-service/utils"
)

type SignupSendRequest struct {
	Email string `json:"email"`
}

type SignupVerifyRequest struct {
	Email string `json:"email"`
	OTPId string `json:"otp_id"`
	OTP   string `json:"otp"`
}

/* ================= SIGNUP SEND OTP ================= */

func SignupSendOTP(w http.ResponseWriter, r *http.Request) {

	var req SignupSendRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.JSON(w, 400, map[string]string{"error": "Invalid request body"})
		return
	}

	if !utils.IsValidEmail(req.Email) {
		utils.JSON(w, 400, map[string]string{"error": "Invalid email format"})
		return
	}

	// 🔥 FIX: Updated to handle new 3-return-value signature
	otpID, remainingSeconds, err := services.GenerateAndSendOTP(req.Email)
	if err != nil {
		utils.JSON(w, 500, map[string]string{"error": err.Error()})
		return
	}

	utils.JSON(w, 200, map[string]interface{}{
		"message":           "Signup OTP sent successfully",
		"otp_id":            otpID,
		"remaining_seconds": remainingSeconds,
	})
}

/* ================= SIGNUP VERIFY OTP ================= */

func SignupVerifyOTP(w http.ResponseWriter, r *http.Request) {

	var req SignupVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.JSON(w, 400, map[string]string{"error": "Invalid request body"})
		return
	}

	if !utils.IsValidEmail(req.Email) || !utils.IsValidOTP(req.OTP) {
		utils.JSON(w, 400, map[string]string{"error": "Invalid email or OTP"})
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
	// Call auth-service to create user
	err = services.CallAuthCreateUser(req.Email)
	if err != nil {
		utils.JSON(w, 500, map[string]string{"error": "Auth service error"})
		return
	}

	utils.JSON(w, 200, map[string]interface{}{
		"message":             "Signup OTP verified",
		"redirect_to_profile": true,
	})
}
