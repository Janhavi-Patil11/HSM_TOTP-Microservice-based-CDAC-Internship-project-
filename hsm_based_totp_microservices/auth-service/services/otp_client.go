package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

type OTPGenerateRequest struct {
	Email string `json:"email"`
}

type OTPVerifyRequest struct {
	OTPId string `json:"otp_id"`
	OTP   string `json:"otp"`
}

func GenerateOTP(email string) (string, error) {

	url := os.Getenv("OTP_SERVICE_URL")
	if url == "" {
		return "", fmt.Errorf("OTP_SERVICE_URL missing")
	}

	reqBody := OTPGenerateRequest{Email: email}
	data, _ := json.Marshal(reqBody)

	resp, err := http.Post(url+"/otp/generate", "application/json", bytes.NewBuffer(data))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("otp-service returned %d", resp.StatusCode)
	}

	var res map[string]string
	json.NewDecoder(resp.Body).Decode(&res)

	return res["otp_id"], nil
}

func VerifyOTP(otpID string, otp string) error {

	url := os.Getenv("OTP_SERVICE_URL")
	if url == "" {
		return fmt.Errorf("OTP_SERVICE_URL missing")
	}

	reqBody := OTPVerifyRequest{
		OTPId: otpID,
		OTP:   otp,
	}

	data, _ := json.Marshal(reqBody)

	resp, err := http.Post(url+"/otp/verify", "application/json", bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("invalid otp")
	}

	return nil
}
