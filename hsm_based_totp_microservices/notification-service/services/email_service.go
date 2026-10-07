package services

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/smtp"
	"time"

	"notificationservice/config"
)

func SendEmail(cfg *config.Config, to, subject, body string) error {

	from := cfg.SMTPEmail
	password := cfg.SMTPPassword

	msg := "From: " + from + "\n" +
		"To: " + to + "\n" +
		"Subject: " + subject + "\n\n" +
		body

	auth := smtp.PlainAuth(
		"",
		from,
		password,
		"smtp.gmail.com",
	)

	// 🔥 FIX: Use custom dialer with explicit timeout.
	// smtp.SendMail() uses net.Dial internally which has NO timeout by default.
	// If Gmail SMTP is slow, the call blocks indefinitely → the otp-service
	// HTTP client (even with 30s timeout) gives up → notification 500 error.
	log.Println("📧 Connecting to SMTP (smtp.gmail.com:587)...")

	dialer := &net.Dialer{
		Timeout: 20 * time.Second,
	}

	conn, err := dialer.Dial("tcp", "smtp.gmail.com:587")
	if err != nil {
		log.Println("❌ SMTP connection failed:", err)
		return fmt.Errorf("SMTP connection failed: %w", err)
	}

	client, err := smtp.NewClient(conn, "smtp.gmail.com")
	if err != nil {
		log.Println("❌ SMTP client creation failed:", err)
		return fmt.Errorf("SMTP client error: %w", err)
	}
	defer client.Close()

	// Start TLS properly
	tlsConfig := &tls.Config{
		ServerName: "smtp.gmail.com",
	}

	if err = client.StartTLS(tlsConfig); err != nil {
		log.Println("❌ SMTP StartTLS failed:", err)
		return fmt.Errorf("SMTP TLS error: %w", err)
	}

	// Authenticate
	if err = client.Auth(auth); err != nil {
		log.Println("❌ SMTP Auth failed:", err)
		return fmt.Errorf("SMTP auth error: %w", err)
	}

	// Set sender
	if err = client.Mail(from); err != nil {
		return fmt.Errorf("SMTP MAIL FROM error: %w", err)
	}

	// Set recipient
	if err = client.Rcpt(to); err != nil {
		return fmt.Errorf("SMTP RCPT TO error: %w", err)
	}

	// Write body
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("SMTP DATA error: %w", err)
	}

	if _, err = fmt.Fprint(w, msg); err != nil {
		return fmt.Errorf("SMTP write error: %w", err)
	}

	if err = w.Close(); err != nil {
		return fmt.Errorf("SMTP close error: %w", err)
	}

	client.Quit()

	log.Println("✅ Email sent successfully to:", to)
	return nil
}
