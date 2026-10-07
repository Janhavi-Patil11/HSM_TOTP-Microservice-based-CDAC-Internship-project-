package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

/* ================= SEND OTP EMAIL ================= */

func SendOTPEmailNotification(email string, otpID string, code string) error {

	message := fmt.Sprintf(
		"Hello,\n\n"+
			"Your Login OTP Verification Details:\n\n"+
			"OTP ID   : %s\n"+
			"OTP Code : %s\n\n"+
			"This OTP is valid for 2 minutes.\n\n"+
			"If you did not request this, please ignore this email.\n\n"+
			"Regards,\n"+
			"HSM-TOTP Security Team",
		otpID,
		code,
	)

	return SendCustomNotification(email, "Login OTP Verification", message)
}

/* ================= SEND CUSTOM EMAIL ================= */

func SendCustomNotification(email string, subject string, message string) error {

	url := os.Getenv("NOTIFICATION_SERVICE_URL")
	if url == "" {
		return fmt.Errorf("NOTIFICATION_SERVICE_URL missing")
	}

	body := map[string]string{
		"user_email": email,
		"title":      subject,
		"message":    message,
	}

	data, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(
		"POST",
		url+"/api/send-email",
		bytes.NewBuffer(data),
	)
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	// 🔥 FIX: Increased timeout from 10s to 30s.
	// SMTP connections (especially Gmail) can take 10-15 seconds.
	// The old 10s timeout was causing the notification service to fail
	// before the email was sent, resulting in HSM key creation without
	// a corresponding email delivery.
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("notification service unreachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("notification service returned status %d", resp.StatusCode)
	}

	return nil
}
