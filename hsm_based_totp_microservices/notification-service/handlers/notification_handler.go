package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"notificationservice/config"
	"notificationservice/database"
	"notificationservice/services"
	"notificationservice/utils"
)

type SingleNotificationRequest struct {
	UserEmail string `json:"user_email"`
	Title     string `json:"title"`
	Message   string `json:"message"`
}

type MultipleNotificationRequest struct {
	UserEmails []string `json:"user_emails"`
	Title      string   `json:"title"`
	Message    string   `json:"message"`
}

//////////////////////////////////////////////////////////
// 🔹 SEND SINGLE NOTIFICATION (SECURE LOGGING)
//////////////////////////////////////////////////////////

func SendSingleNotification(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		log.Println("📩 /api/send-email endpoint hit (internal - email only, no DB save)")

		var req SingleNotificationRequest

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			log.Println("❌ Invalid JSON:", err)
			utils.ErrorResponse(w, 400, "Invalid JSON")
			return
		}

		// 🔐 DO NOT log full request (contains OTP)
		log.Println("📨 Email request received for:", req.UserEmail)

		if req.UserEmail == "" || req.Message == "" {
			log.Println("❌ Missing user_email or message")
			utils.ErrorResponse(w, 400, "user_email and message required")
			return
		}

		if req.Title == "" {
			req.Title = "ECS Notification"
		}

		// ⚠️ DO NOT save OTP emails to ecs_notifications table!
		// OTP data should only exist in HSM memory and be sent via email.
		// Only admin notifications get saved to the database.

		// Send Email only
		emailErr := services.SendEmail(cfg, req.UserEmail, req.Title, req.Message)
		if emailErr != nil {
			log.Println("❌ Email sending failed:", emailErr)
			utils.ErrorResponse(w, 500, "Email sending failed")
			return
		}

		log.Println("✅ Email sent successfully to:", req.UserEmail)

		utils.JSONResponse(w, 200, map[string]string{
			"message": "Email sent successfully",
		})
	}
}

//////////////////////////////////////////////////////////
// 🔹 SEND MULTIPLE NOTIFICATIONS (SECURE LOGGING)
//////////////////////////////////////////////////////////

func SendMultipleNotification(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		log.Println("📩 /api/admin/notify-multiple endpoint hit")

		var req MultipleNotificationRequest

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			log.Println("❌ Invalid JSON:", err)
			utils.ErrorResponse(w, 400, "Invalid JSON")
			return
		}

		if len(req.UserEmails) == 0 || req.Message == "" {
			log.Println("❌ Missing user_emails or message")
			utils.ErrorResponse(w, 400, "user_emails and message required")
			return
		}

		if req.Title == "" {
			req.Title = " ECS Notification"
		}

		for _, email := range req.UserEmails {

			_, dbErr := database.DB.Exec(
				`INSERT INTO ecs_notifications(user_email,title,message,type,is_read,created_at)
				 VALUES($1,$2,$3,'email',false,$4)`,
				email, req.Title, req.Message, time.Now(),
			)

			if dbErr != nil {
				log.Println("❌ DB Insert Failed for:", email, "Error:", dbErr)
				continue
			}

			emailErr := services.SendEmail(cfg, email, req.Title, req.Message)
			if emailErr != nil {
				log.Println("❌ Email sending failed for:", email, "Error:", emailErr)
				continue
			}

			log.Println("✅ Notification sent to:", email)
		}

		utils.JSONResponse(w, 200, map[string]string{
			"message": "Notifications sent to multiple users",
		})
	}
}
