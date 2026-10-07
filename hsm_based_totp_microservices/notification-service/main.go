package main

import (
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"

	"notificationservice/config"
	"notificationservice/database"
	"notificationservice/handlers"
	"notificationservice/middleware"
)

func main() {

	// Load .env
	_ = godotenv.Load()

	// Load Config
	cfg := config.LoadConfig()

	// Connect Database
	database.ConnectDB(cfg)

	mux := http.NewServeMux()

	/* ================= INTERNAL ROUTE (OTP → Notification) ================= */

	// 🔹 Internal Email Route (Used by OTP Service)
	mux.HandleFunc("/api/send-email",
		handlers.SendSingleNotification(cfg),
	)

	/* ================= ADMIN ROUTES ================= */

	// 🔹 Admin Send Single Notification
	mux.HandleFunc("/api/admin/notify-single",
		middleware.AdminMiddleware(
			handlers.SendSingleNotification(cfg),
		),
	)

	// 🔹 Admin Send Multiple Notifications
	mux.HandleFunc("/api/admin/notify-multiple",
		middleware.AdminMiddleware(
			handlers.SendMultipleNotification(cfg),
		),
	)

	/* ================= ECS NOTIFICATION TEMPLATE (Frontend fetches message) ================= */

	mux.HandleFunc("/api/ecs-notification",
		handlers.GetNotificationTemplate(cfg),
	)

	/* ================= FRONTEND SEND NOTIFICATION ================= */

	mux.HandleFunc("/api/send-notification",
		handlers.SendNotificationFromFrontend(cfg),
	)

	// Get Port
	port := os.Getenv("PORT")
	if port == "" {
		port = "9092"
	}

	log.Println("🚀 Notification Service running on :", port)

	// Wrap with CORS
	handler := middleware.CORS(mux)

	// Start Server
	log.Fatal(http.ListenAndServe("0.0.0.0:"+port, handler))
}
