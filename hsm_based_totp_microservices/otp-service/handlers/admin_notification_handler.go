package handlers

import (
	"encoding/json"
	"net/http"

	"otp-service/services"
	"otp-service/utils"
)

type AdminNotificationRequest struct {
	Email   string `json:"email"`
	Subject string `json:"subject"`
	Message string `json:"message"`
}

type AdminNotificationMultiRequest struct {
	Emails  []string `json:"emails"`
	Subject string   `json:"subject"`
	Message string   `json:"message"`
}

/* ================= ADMIN SEND NOTIFICATION SINGLE ================= */

func AdminSendNotification(w http.ResponseWriter, r *http.Request) {

	var req AdminNotificationRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.JSON(w, 400, map[string]string{"error": "Invalid request body"})
		return
	}

	if !utils.IsValidEmail(req.Email) {
		utils.JSON(w, 400, map[string]string{"error": "Invalid email"})
		return
	}

	if req.Subject == "" || req.Message == "" {
		utils.JSON(w, 400, map[string]string{"error": "Subject and message required"})
		return
	}

	if err := services.SendCustomNotification(req.Email, req.Subject, req.Message); err != nil {
		utils.JSON(w, 500, map[string]string{"error": err.Error()})
		return
	}

	utils.JSON(w, 200, map[string]string{
		"message": "Notification sent successfully",
	})
}

/* ================= ADMIN SEND NOTIFICATION MULTI ================= */

func AdminSendNotificationMulti(w http.ResponseWriter, r *http.Request) {

	var req AdminNotificationMultiRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.JSON(w, 400, map[string]string{"error": "Invalid request body"})
		return
	}

	if len(req.Emails) == 0 || req.Subject == "" || req.Message == "" {
		utils.JSON(w, 400, map[string]string{"error": "Emails, subject and message required"})
		return
	}

	for _, email := range req.Emails {

		if !utils.IsValidEmail(email) {
			continue
		}

		_ = services.SendCustomNotification(email, req.Subject, req.Message)
	}

	utils.JSON(w, 200, map[string]string{
		"message": "Notifications sent successfully",
	})
}
