package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

type NotificationRequest struct {
	Emails  []string `json:"emails"`
	Subject string   `json:"subject"`
	Message string   `json:"message"`
}

func SendNotificationToEmployees(token string, emails []string, subject string, message string) error {

	url := os.Getenv("NOTIFICATION_SERVICE_URL")
	if url == "" {
		return fmt.Errorf("NOTIFICATION_SERVICE_URL missing")
	}

	reqBody := NotificationRequest{
		Emails:  emails,
		Subject: subject,
		Message: message,
	}

	data, _ := json.Marshal(reqBody)

	req, err := http.NewRequest("POST", url+"/notify/send-multi", bytes.NewBuffer(data))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("notification-service returned %d", resp.StatusCode)
	}

	return nil
}
