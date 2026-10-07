package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"auth-service/database"
)

/* ================== GET USER PROFILE ================== */

func GetUserProfile(w http.ResponseWriter, r *http.Request) {

	email := r.Header.Get("X-User-Email")
	if email == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	row := database.DB.QueryRow(`
		SELECT 
			id,
			email,
			COALESCE(name,''),
			role,
			is_profile_complete,
			COALESCE(employee_id,''),
			COALESCE(employee_name,''),
			COALESCE(phone_number,''),
			COALESCE(type_of_clearance,''),
			COALESCE(position_level,''),
			COALESCE(designation,''),
			COALESCE(current_location,''),
			COALESCE(to_char(date_of_hired, 'YYYY-MM-DD'),''),
			COALESCE(to_char(date_of_clearance, 'YYYY-MM-DD'),''),
			COALESCE(clearance_area,'')
		FROM users
		WHERE email=$1
	`, email)

	var user struct {
		UserID            int    `json:"user_id"`
		Email             string `json:"email"`
		Name              string `json:"name"`
		Role              string `json:"role"`
		IsProfileComplete bool   `json:"is_profile_complete"`

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

	err := row.Scan(
		&user.UserID,
		&user.Email,
		&user.Name,
		&user.Role,
		&user.IsProfileComplete,
		&user.EmployeeID,
		&user.EmployeeName,
		&user.PhoneNumber,
		&user.TypeOfClearance,
		&user.PositionLevel,
		&user.Designation,
		&user.CurrentLocation,
		&user.DateOfHired,
		&user.DateOfClearance,
		&user.ClearanceArea,
	)

	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

/* ================== UPDATE EMPLOYEE PROFILE (SELF) ================== */

func UpdateEmployeeProfile(w http.ResponseWriter, r *http.Request) {

	email := r.Header.Get("X-User-Email")
	if email == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		Name        string `json:"name"`
		PhoneNumber string `json:"phone_number"`
		Password    string `json:"password"`
		Email       string `json:"email"` // will be ignored
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// ---------------- VALIDATIONS ----------------

	req.Name = strings.TrimSpace(req.Name)
	if req.Name != "" {
		if len(req.Name) < 3 || len(req.Name) > 50 {
			http.Error(w, "Name must be between 3 and 50 characters", http.StatusBadRequest)
			return
		}
	}

	if req.PhoneNumber != "" {
		if !isValidPhoneNumber(req.PhoneNumber) {
			http.Error(w, "Phone number must be exactly 10 digits", http.StatusBadRequest)
			return
		}
	}

	var passwordHash string
	if req.Password != "" {
		valid, msg := isValidPassword(req.Password)
		if !valid {
			http.Error(w, msg, http.StatusBadRequest)
			return
		}

		hash, err := hashPassword(req.Password)
		if err != nil {
			http.Error(w, "Failed to process password", http.StatusInternalServerError)
			return
		}
		passwordHash = hash
	}

	// ---------------- UPDATE ONLY ALLOWED FIELDS ----------------

	_, err := database.DB.Exec(`
		UPDATE users SET
			name = COALESCE(NULLIF($1,''), name),
			phone_number = COALESCE(NULLIF($2,''), phone_number),
			password_hash = COALESCE(NULLIF($3,''), password_hash),
			updated_at = NOW()
		WHERE email = $4
	`,
		req.Name,
		req.PhoneNumber,
		passwordHash,
		email,
	)

	if err != nil {
		http.Error(w, "Failed to update profile", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"message": "Profile updated successfully",
	})
}
