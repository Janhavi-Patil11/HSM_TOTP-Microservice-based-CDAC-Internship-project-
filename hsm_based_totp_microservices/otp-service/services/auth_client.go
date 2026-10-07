package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

/* ================= SIGNUP CREATE USER ================= */

func CallAuthCreateUser(email string) error {

	authURL := os.Getenv("AUTH_SERVICE_URL")
	if authURL == "" {
		return fmt.Errorf("AUTH_SERVICE_URL missing")
	}

	payload := map[string]string{
		"email": email,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	resp, err := http.Post(
		authURL+"/api/signup/create-user",
		"application/json",
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("auth service user creation failed with status %d", resp.StatusCode)
	}

	return nil
}

/* ================= FORGOT CREATE SESSION ================= */

func CallAuthCreateResetSession(email, otpID string) (string, error) {

	authURL := os.Getenv("AUTH_SERVICE_URL")
	if authURL == "" {
		return "", fmt.Errorf("AUTH_SERVICE_URL missing")
	}

	payload := map[string]string{
		"email":  email,
		"otp_id": otpID,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	resp, err := http.Post(
		authURL+"/api/forgot/create-session",
		"application/json",
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("auth service reset session failed with status %d", resp.StatusCode)
	}

	var result struct {
		SessionToken string `json:"session_token"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	return result.SessionToken, nil
}

/* ================= LOGIN CREATE SESSION ================= */

func CallAuthCreateLoginSession(email, otpID string) (string, error) {

	authURL := os.Getenv("AUTH_SERVICE_URL")
	if authURL == "" {
		return "", fmt.Errorf("AUTH_SERVICE_URL missing")
	}

	payload := map[string]string{
		"email":  email,
		"otp_id": otpID,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	resp, err := http.Post(
		authURL+"/api/login/create-session",
		"application/json",
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("auth login session failed with status %d", resp.StatusCode)
	}

	var result struct {
		SessionToken string `json:"session_token"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	return result.SessionToken, nil
}
