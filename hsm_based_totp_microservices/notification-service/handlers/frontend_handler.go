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

//////////////////////////////////////////////////////////
// 🔹 GET NOTIFICATION TEMPLATE FROM ecs_notifications
//////////////////////////////////////////////////////////

func GetNotificationTemplate(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		log.Println("📋 /api/ecs-notification template request")

		var message string
		err := database.DB.QueryRow(
			`SELECT COALESCE(message, '') FROM ecs_notifications 
			 WHERE type='template' 
			 ORDER BY created_at DESC LIMIT 1`,
		).Scan(&message)

		if err != nil {
			log.Println("⚠️ No notification template found:", err)
			utils.JSONResponse(w, 200, map[string]string{
				"message": "",
			})
			return
		}

		utils.JSONResponse(w, 200, map[string]string{
			"message": message,
		})
	}
}

//////////////////////////////////////////////////////////
// 🔹 SEND NOTIFICATION FROM FRONTEND (SendNotification page)
//////////////////////////////////////////////////////////

type FrontendNotificationRequest struct {
	Emails  []string `json:"emails"`
	Message string   `json:"message"`
}

func SendNotificationFromFrontend(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		log.Println("📩 /api/send-notification endpoint hit")

		var req FrontendNotificationRequest

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			log.Println("❌ Invalid JSON:", err)
			utils.ErrorResponse(w, 400, "Invalid JSON")
			return
		}

		if len(req.Emails) == 0 || req.Message == "" {
			log.Println("❌ Missing emails or message")
			utils.ErrorResponse(w, 400, "emails and message required")
			return
		}

		title := "ECS Notification"

		for _, email := range req.Emails {
			// Save to DB
			_, dbErr := database.DB.Exec(
				`INSERT INTO ecs_notifications(user_email,title,message,type,is_read,created_at)
				 VALUES($1,$2,$3,'email',false,$4)`,
				email, title, req.Message, time.Now(),
			)
			if dbErr != nil {
				log.Println("❌ DB Insert Failed for:", email, "Error:", dbErr)
				continue
			}

			// Send Email
			emailErr := services.SendEmail(cfg, email, title, req.Message)
			if emailErr != nil {
				log.Println("❌ Email sending failed for:", email, "Error:", emailErr)
				continue
			}

			log.Println("✅ Notification sent to:", email)
		}

		utils.JSONResponse(w, 200, map[string]string{
			"message": "Notifications sent successfully",
		})
	}
}
