package utils

import (
	"regexp"
	"strings"
)

func NormalizeEmail(email string) string {
	return strings.TrimSpace(strings.ToLower(email))
}

func IsValidEmail(email string) bool {
	email = strings.TrimSpace(email)

	if len(email) < 8 || len(email) > 70 {
		return false
	}

	re := regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return re.MatchString(email)
}

func IsValidPhoneNumber(phone string) bool {
	return regexp.MustCompile(`^[0-9]{10}$`).MatchString(strings.TrimSpace(phone))
}

func IsValidPassword(password string) bool {

	password = strings.TrimSpace(password)

	if len(password) < 8 || len(password) > 30 {
		return false
	}

	if !regexp.MustCompile(`[A-Z]`).MatchString(password) {
		return false
	}

	if !regexp.MustCompile(`[a-z]`).MatchString(password) {
		return false
	}

	if !regexp.MustCompile(`[0-9]`).MatchString(password) {
		return false
	}

	if !regexp.MustCompile(`[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>/?]`).MatchString(password) {
		return false
	}

	return true
}
