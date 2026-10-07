package utils

import "regexp"

func IsValidEmail(email string) bool {
	re := regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	return re.MatchString(email)
}

func IsValidOTP(otp string) bool {
	re := regexp.MustCompile(`^[0-9]{6}$`)
	return re.MatchString(otp)
}
