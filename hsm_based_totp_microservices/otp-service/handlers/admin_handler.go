package handlers

import (
	"encoding/json"
	"net/http"

	"otp-service/services"
	"otp-service/utils"
)

type AdminSendOTPRequest struct {
	Email string `json:"email"`
}

type AdminSendOTPMultiRequest struct {
	Emails []string `json:"emails"`
}

/* ================= ADMIN SEND OTP SINGLE ================= */

func AdminSendOTP(w http.ResponseWriter, r *http.Request) {

	var req AdminSendOTPRequest
	json.NewDecoder(r.Body).Decode(&req)

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
		"message":           "OTP sent",
		"otp_id":            otpID,
		"remaining_seconds": remainingSeconds,
	})
}

/* ================= ADMIN SEND OTP MULTI ================= */

func AdminSendOTPMulti(w http.ResponseWriter, r *http.Request) {

	var req AdminSendOTPMultiRequest
	json.NewDecoder(r.Body).Decode(&req)

	results := []map[string]string{}

	for _, email := range req.Emails {

		// 🔥 FIX: Updated to handle new 3-return-value signature
		otpID, _, err := services.GenerateAndSendOTP(email)
		if err != nil {
			results = append(results, map[string]string{
				"email":  email,
				"status": "failed",
			})
			continue
		}

		results = append(results, map[string]string{
			"email":  email,
			"otp_id": otpID,
			"status": "success",
		})
	}

	utils.JSON(w, 200, map[string]interface{}{
		"results": results,
	})
}
