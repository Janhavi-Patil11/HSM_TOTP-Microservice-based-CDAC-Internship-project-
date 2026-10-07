package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"auth-service/auth"
	"auth-service/database"

	"golang.org/x/crypto/bcrypt"
)

/* ================== CONSTANTS ================== */

const (
	MaxEmailLength     = 50
	MinPasswordLength  = 8
	MaxPasswordLength  = 30
	MaxEmployeeNameLen = 30
	EmployeeIDLength   = 6
	PhoneNumberLength  = 10

	ResetSessionExpiry = 10 * time.Minute
)

/* ================== HELPERS ================== */

func normalizeEmail(email string) string {
	return strings.TrimSpace(strings.ToLower(email))
}

func isValidEmail(email string) bool {
	email = strings.TrimSpace(email)
	if email == "" || len(email) > MaxEmailLength {
		return false
	}

	re := regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return re.MatchString(email)
}

func isRegisteredUser(email string) bool {
	var exists bool
	err := database.DB.QueryRow(
		`SELECT EXISTS(SELECT 1 FROM users WHERE email=$1)`,
		email,
	).Scan(&exists)

	return err == nil && exists
}

func getUserRole(email string) (string, error) {
	var role string
	err := database.DB.QueryRow(
		`SELECT role FROM users WHERE email=$1`,
		email,
	).Scan(&role)

	return role, err
}

func getUserPasswordHash(email string) (string, bool) {
	var hash string
	err := database.DB.QueryRow(
		`SELECT password_hash FROM users WHERE email=$1`,
		email,
	).Scan(&hash)

	return hash, err == nil
}

func isProfileComplete(email string) (bool, error) {
	var complete bool
	err := database.DB.QueryRow(
		`SELECT is_profile_complete FROM users WHERE email=$1`,
		email,
	).Scan(&complete)

	return complete, err
}

func checkPassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func isValidPassword(password string) (bool, string) {

	password = strings.TrimSpace(password)

	if password == "" {
		return false, "Password is required"
	}

	if len(password) < MinPasswordLength {
		return false, fmt.Sprintf("Password must be at least %d characters", MinPasswordLength)
	}

	if len(password) > MaxPasswordLength {
		return false, fmt.Sprintf("Password must not exceed %d characters", MaxPasswordLength)
	}

	if !regexp.MustCompile(`[A-Z]`).MatchString(password) {
		return false, "Password must contain at least 1 uppercase letter"
	}

	if !regexp.MustCompile(`[a-z]`).MatchString(password) {
		return false, "Password must contain at least 1 lowercase letter"
	}

	if !regexp.MustCompile(`[0-9]`).MatchString(password) {
		return false, "Password must contain at least 1 number"
	}

	if !regexp.MustCompile(`[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]`).MatchString(password) {
		return false, "Password must contain at least 1 special character"
	}

	return true, ""
}

func normalizePhoneNumber(phone string) string {
	phone = strings.TrimSpace(phone)
	phone = strings.ReplaceAll(phone, " ", "")
	phone = strings.TrimPrefix(phone, "+91")
	return phone
}

func isValidPhoneNumber(phone string) bool {
	phone = normalizePhoneNumber(phone)
	return regexp.MustCompile(`^[0-9]{10}$`).MatchString(phone)
}

func isValidEmployeeID(empID string) bool {
	empID = strings.TrimSpace(strings.ToUpper(empID))
	return len(empID) > 0 && len(empID) <= EmployeeIDLength &&
		regexp.MustCompile(`^[A-Z0-9]+$`).MatchString(empID)
}

func generateSessionToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

/* ================== SIGNUP USER CREATE (CALLED BY OTP SERVICE) ================== */

func SignupCreateUser(w http.ResponseWriter, r *http.Request) {

	var req struct {
		Email string `json:"email"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	req.Email = normalizeEmail(req.Email)

	if !isValidEmail(req.Email) {
		http.Error(w, "Invalid email format", http.StatusBadRequest)
		return
	}

	// If already exists no issue
	_, err := database.DB.Exec(`
		INSERT INTO users (email, role, is_profile_complete, created_at, updated_at)
		VALUES ($1, 'employee', false, NOW(), NOW())
		ON CONFLICT (email) DO NOTHING
	`, req.Email)

	if err != nil {
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"message": "User created successfully",
	})
}

/* ================== LOGIN (PASSWORD CHECK ONLY) ================== */

func Login(w http.ResponseWriter, r *http.Request) {

	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	req.Email = normalizeEmail(req.Email)
	req.Password = strings.TrimSpace(req.Password)

	if !isValidEmail(req.Email) {
		http.Error(w, "Invalid email format", http.StatusBadRequest)
		return
	}

	isComplete, err := isProfileComplete(req.Email)
	if err != nil {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}

	if !isComplete {
		http.Error(w, "Please complete your profile first", http.StatusForbidden)
		return
	}

	hash, exists := getUserPasswordHash(req.Email)
	if !exists || !checkPassword(hash, req.Password) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"message": "Password verified. Proceed to OTP.",
	})
}

/* ================== LOGIN SESSION CREATE (CALLED BY OTP SERVICE) ================== */

func CreateLoginSession(w http.ResponseWriter, r *http.Request) {

	var req struct {
		Email string `json:"email"`
		OtpID string `json:"otp_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	req.Email = normalizeEmail(req.Email)

	if !isRegisteredUser(req.Email) {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}

	// delete old login sessions
	database.DB.Exec(`DELETE FROM login_sessions WHERE email=$1`, req.Email)

	sessionToken := generateSessionToken()
	expiresAt := time.Now().Add(5 * time.Minute)

	_, err := database.DB.Exec(`
		INSERT INTO login_sessions (email, otp_verified, session_token, expires_at, created_at)
		VALUES ($1, true, $2, $3, NOW())
	`,
		req.Email,
		sessionToken,
		expiresAt,
	)

	if err != nil {
		http.Error(w, "Failed to create login session", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"session_token": sessionToken,
		"expires_at":    expiresAt,
	})
}

/* ==================Final JWT generation  login ================== */

func FinalLogin(w http.ResponseWriter, r *http.Request) {

	var req struct {
		Email        string `json:"email"`
		SessionToken string `json:"session_token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	req.Email = normalizeEmail(req.Email)

	if req.Email == "" || req.SessionToken == "" {
		http.Error(w, "Email and session_token required", http.StatusBadRequest)
		return
	}

	// check login session
	var otpVerified bool
	var expiresAt time.Time

	err := database.DB.QueryRow(`
		SELECT otp_verified, expires_at
		FROM login_sessions
		WHERE email=$1 AND session_token=$2
	`,
		req.Email, req.SessionToken,
	).Scan(&otpVerified, &expiresAt)

	if err != nil {
		http.Error(w, "Invalid session", http.StatusUnauthorized)
		return
	}

	if !otpVerified {
		http.Error(w, "OTP not verified", http.StatusUnauthorized)
		return
	}

	if time.Now().After(expiresAt) {
		http.Error(w, "Session expired", http.StatusUnauthorized)
		return
	}

	role, _ := getUserRole(req.Email)

	token, _ := auth.GenerateJWT(req.Email, role)

	// delete session after login
	database.DB.Exec(`DELETE FROM login_sessions WHERE email=$1`, req.Email)

	json.NewEncoder(w).Encode(map[string]string{
		"message": "Login successful",
		"token":   token,
		"role":    role,
		"email":   req.Email,
	})
}

func CompleteProfile(w http.ResponseWriter, r *http.Request) {

	var req struct {
		Email           string `json:"email"`
		Password        string `json:"password"`
		EmployeeID      string `json:"employee_id"`
		EmployeeName    string `json:"employee_name"`
		PhoneNumber     string `json:"phone_number"`
		TypeOfClearance string `json:"type_of_clearance"`
		PositionLevel   string `json:"position_level"`
		Designation     string `json:"designation"`
		CurrentLocation string `json:"current_location"`
		DateOfHired     string `json:"date_of_hired"`
		DateOfClearance string `json:"date_of_clearance"`
		ClearanceArea   string `json:"clearance_area"`
	}

	// Decode request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	req.Email = normalizeEmail(req.Email)

	// -------- VALIDATIONS --------

	if !isValidEmail(req.Email) {
		http.Error(w, "Invalid email format", http.StatusBadRequest)
		return
	}

	valid, msg := isValidPassword(req.Password)
	if !valid {
		http.Error(w, msg, http.StatusBadRequest)
		return
	}

	if !isValidEmployeeID(req.EmployeeID) {
		http.Error(w, "Employee ID must be alphanumeric and max 6 characters", http.StatusBadRequest)
		return
	}

	req.EmployeeName = strings.TrimSpace(req.EmployeeName)
	if len(req.EmployeeName) == 0 || len(req.EmployeeName) > MaxEmployeeNameLen {
		http.Error(w, "Employee name is invalid", http.StatusBadRequest)
		return
	}

	if !isValidPhoneNumber(req.PhoneNumber) {
		http.Error(w, "Phone number must be exactly 10 digits", http.StatusBadRequest)
		return
	}

	// -------- CHECK USER EXISTS --------

	var isComplete bool
	err := database.DB.QueryRow(
		`SELECT is_profile_complete FROM users WHERE email=$1`,
		req.Email,
	).Scan(&isComplete)

	if err != nil {
		http.Error(w, "User not found. Please signup first.", http.StatusNotFound)
		return
	}

	if isComplete {
		http.Error(w, "Profile already completed. Please login.", http.StatusBadRequest)
		return
	}

	// -------- CHECK EMPLOYEE ID DUPLICATE --------

	var exists bool
	database.DB.QueryRow(
		`SELECT EXISTS(SELECT 1 FROM users WHERE employee_id=$1)`,
		req.EmployeeID,
	).Scan(&exists)

	if exists {
		http.Error(w, "Employee ID already exists", http.StatusConflict)
		return
	}

	// -------- HASH PASSWORD --------

	hash, err := hashPassword(req.Password)
	if err != nil {
		http.Error(w, "Failed to process password", http.StatusInternalServerError)
		return
	}

	// -------- UPDATE PROFILE --------

	result, err := database.DB.Exec(`
		UPDATE users SET
			password_hash=$1,
			name=$2,
			employee_id=$3,
			employee_name=$4,
			phone_number=$5,
			type_of_clearance=$6,
			position_level=$7,
			designation=$8,
			current_location=$9,
			date_of_hired=$10::date,
			date_of_clearance=$11::date,
			clearance_area=$12,
			is_profile_complete=true,
			updated_at=NOW()
		WHERE email=$13
	`,
		hash,
		req.EmployeeName,
		req.EmployeeID,
		req.EmployeeName,
		req.PhoneNumber,
		req.TypeOfClearance,
		req.PositionLevel,
		req.Designation,
		req.CurrentLocation,
		req.DateOfHired,
		req.DateOfClearance,
		req.ClearanceArea,
		req.Email,
	)

	if err != nil {
		http.Error(w, "Failed to complete profile", http.StatusInternalServerError)
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		http.Error(w, "Profile update failed", http.StatusInternalServerError)
		return
	}

	// -------- SUCCESS RESPONSE --------

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Profile completed successfully",
	})
}

/* ================== FORGOT PASSWORD CREATE SESSION (CALLED BY OTP SERVICE) ================== */

func CreateResetSession(w http.ResponseWriter, r *http.Request) {

	var req struct {
		Email string `json:"email"`
		OTPID string `json:"otp_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	req.Email = normalizeEmail(req.Email)
	req.OTPID = strings.TrimSpace(req.OTPID)

	if !isValidEmail(req.Email) {
		http.Error(w, "Invalid email format", http.StatusBadRequest)
		return
	}

	if req.OTPID == "" {
		http.Error(w, "otp_id is required", http.StatusBadRequest)
		return
	}

	if !isRegisteredUser(req.Email) {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}

	// delete old sessions
	database.DB.Exec(`DELETE FROM password_reset_sessions WHERE user_email=$1`, req.Email)

	sessionToken := generateSessionToken()
	expiresAt := time.Now().Add(ResetSessionExpiry)

	_, err := database.DB.Exec(`
		INSERT INTO password_reset_sessions (user_email, otp_id, is_verified, session_token, expires_at, created_at)
		VALUES ($1,$2,true,$3,$4,NOW())
	`,
		req.Email,
		req.OTPID,
		sessionToken,
		expiresAt,
	)

	if err != nil {
		http.Error(w, "Failed to create reset session", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":       "Reset session created",
		"session_token": sessionToken,
		"expires_at":    expiresAt,
	})
}

/* ================== RESET PASSWORD ================== */

func ResetPassword(w http.ResponseWriter, r *http.Request) {

	var req struct {
		Email        string `json:"email"`
		SessionToken string `json:"session_token"`
		NewPassword  string `json:"new_password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	req.Email = normalizeEmail(req.Email)
	req.SessionToken = strings.TrimSpace(req.SessionToken)
	req.NewPassword = strings.TrimSpace(req.NewPassword)

	if req.Email == "" || req.SessionToken == "" || req.NewPassword == "" {
		http.Error(w, "email, session_token and new_password are required", http.StatusBadRequest)
		return
	}

	if !isValidEmail(req.Email) {
		http.Error(w, "Invalid email format", http.StatusBadRequest)
		return
	}

	valid, msg := isValidPassword(req.NewPassword)
	if !valid {
		http.Error(w, msg, http.StatusBadRequest)
		return
	}

	// verify session
	var isVerified bool
	var expiresAt time.Time

	err := database.DB.QueryRow(`
		SELECT is_verified, expires_at
		FROM password_reset_sessions
		WHERE user_email=$1 AND session_token=$2
	`,
		req.Email, req.SessionToken,
	).Scan(&isVerified, &expiresAt)

	if err != nil {
		http.Error(w, "Invalid or expired session token", http.StatusUnauthorized)
		return
	}

	if !isVerified {
		http.Error(w, "OTP not verified", http.StatusUnauthorized)
		return
	}

	if time.Now().After(expiresAt) {
		http.Error(w, "Session expired", http.StatusUnauthorized)
		return
	}

	// hash password
	newHash, err := hashPassword(req.NewPassword)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	_, err = database.DB.Exec(`
		UPDATE users SET password_hash=$1, updated_at=NOW()
		WHERE email=$2
	`,
		newHash, req.Email,
	)

	if err != nil {
		http.Error(w, "Failed to update password", http.StatusInternalServerError)
		return
	}

	// delete session after reset
	database.DB.Exec(`DELETE FROM password_reset_sessions WHERE user_email=$1`, req.Email)

	json.NewEncoder(w).Encode(map[string]string{
		"message": "Password reset successfully",
	})
}
