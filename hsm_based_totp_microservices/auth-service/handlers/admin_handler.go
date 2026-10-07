package handlers

import (
	"encoding/json"
	"log"
	"net/http"

	"auth-service/database"
)

/* ================== GET ALL EMPLOYEES ================== */

func GetAllEmployees(w http.ResponseWriter, r *http.Request) {

	email := r.Header.Get("X-User-Email")
	role, _ := getUserRole(email)

	if role != "admin" {
		http.Error(w, "Forbidden: Admin access required", http.StatusForbidden)
		return
	}

	rows, err := database.DB.Query(`
		SELECT
			id,
			email,
			COALESCE(name, ''),
			role,
			is_profile_complete,
			COALESCE(employee_id, ''),
			COALESCE(employee_name, ''),
			COALESCE(phone_number, ''),
			COALESCE(type_of_clearance, ''),
			COALESCE(position_level, ''),
			COALESCE(designation, ''),
			COALESCE(current_location, ''),
			COALESCE(to_char(date_of_hired, 'YYYY-MM-DD'), ''),
			COALESCE(to_char(date_of_clearance, 'YYYY-MM-DD'), ''),
			COALESCE(clearance_area, '')
		FROM users
		WHERE role='employee'
		ORDER BY id
	`)

	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type Employee struct {
		UserID            int    `json:"user_id"`
		Email             string `json:"email"`
		Name              string `json:"name"`
		Role              string `json:"role"`
		IsProfileComplete bool   `json:"is_profile_complete"`
		EmployeeID        string `json:"employee_id"`
		EmployeeName      string `json:"employee_name"`
		PhoneNumber       string `json:"phone_number"`
		TypeOfClearance   string `json:"type_of_clearance"`
		PositionLevel     string `json:"position_level"`
		Designation       string `json:"designation"`
		CurrentLocation   string `json:"current_location"`
		DateOfHired       string `json:"date_of_hired"`
		DateOfClearance   string `json:"date_of_clearance"`
		ClearanceArea     string `json:"clearance_area"`
	}

	var employees []Employee

	for rows.Next() {
		var e Employee
		if err := rows.Scan(
			&e.UserID,
			&e.Email,
			&e.Name,
			&e.Role,
			&e.IsProfileComplete,
			&e.EmployeeID,
			&e.EmployeeName,
			&e.PhoneNumber,
			&e.TypeOfClearance,
			&e.PositionLevel,
			&e.Designation,
			&e.CurrentLocation,
			&e.DateOfHired,
			&e.DateOfClearance,
			&e.ClearanceArea,
		); err != nil {
			http.Error(w, "Failed to read employee data", http.StatusInternalServerError)
			return
		}
		employees = append(employees, e)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(employees)
}

/* ================== ADMIN: ADD EMPLOYEE ================== */

func AddEmployee(w http.ResponseWriter, r *http.Request) {

	email := r.Header.Get("X-User-Email")
	role, _ := getUserRole(email)

	if role != "admin" {
		http.Error(w, "Forbidden: Admin access required", http.StatusForbidden)
		return
	}

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

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	req.Email = normalizeEmail(req.Email)

	if !isValidEmail(req.Email) {
		http.Error(w, "Invalid email format", http.StatusBadRequest)
		return
	}

	valid, errMsg := isValidPassword(req.Password)
	if !valid {
		http.Error(w, errMsg, http.StatusBadRequest)
		return
	}

	if !isValidEmployeeID(req.EmployeeID) {
		http.Error(w, "Invalid employee ID", http.StatusBadRequest)
		return
	}

	if !isValidPhoneNumber(req.PhoneNumber) {
		http.Error(w, "Phone number must be exactly 10 digits", http.StatusBadRequest)
		return
	}

	if isRegisteredUser(req.Email) {
		http.Error(w, "Email already exists", http.StatusConflict)
		return
	}

	var empIDExists bool
	database.DB.QueryRow(
		`SELECT EXISTS (SELECT 1 FROM users WHERE employee_id=$1)`,
		req.EmployeeID,
	).Scan(&empIDExists)

	if empIDExists {
		http.Error(w, "Employee ID already exists", http.StatusConflict)
		return
	}

	hash, err := hashPassword(req.Password)
	if err != nil {
		http.Error(w, "Failed to process password", http.StatusInternalServerError)
		return
	}

	_, err = database.DB.Exec(`
		INSERT INTO users (
			email,
			password_hash,
			name,
			role,
			is_profile_complete,
			employee_id,
			employee_name,
			phone_number,
			type_of_clearance,
			position_level,
			designation,
			current_location,
			date_of_hired,
			date_of_clearance,
			clearance_area,
			created_at,
			updated_at
		) VALUES (
			$1,$2,$3,'employee',true,
			$4,$5,$6,$7,$8,$9,$10,
			$11::date,$12::date,$13,
			NOW(),NOW()
		)`,
		req.Email,
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
	)

	if err != nil {
		http.Error(w, "Failed to add employee", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Employee added successfully",
	})
}

/* ================== ADMIN: UPDATE EMPLOYEE ================== */

func UpdateEmployeeByAdmin(w http.ResponseWriter, r *http.Request) {

	adminEmail := r.Header.Get("X-User-Email")
	role, _ := getUserRole(adminEmail)

	if role != "admin" {
		http.Error(w, "Forbidden: Admin access required", http.StatusForbidden)
		return
	}

	var req struct {
		UserID          int    `json:"user_id"`
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

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// VALIDATION
	if req.Email != "" && !isValidEmail(req.Email) {
		http.Error(w, "Invalid email format", http.StatusBadRequest)
		return
	}

	if req.Password != "" {
		valid, errMsg := isValidPassword(req.Password)
		if !valid {
			http.Error(w, errMsg, http.StatusBadRequest)
			return
		}
	}

	if req.PhoneNumber != "" && !isValidPhoneNumber(req.PhoneNumber) {
		http.Error(w, "Invalid phone number", http.StatusBadRequest)
		return
	}

	if req.EmployeeID != "" && !isValidEmployeeID(req.EmployeeID) {
		http.Error(w, "Invalid employee ID", http.StatusBadRequest)
		return
	}

	// PASSWORD UPDATE
	if req.Password != "" {
		hash, err := hashPassword(req.Password)
		if err != nil {
			http.Error(w, "Failed to process password", http.StatusInternalServerError)
			return
		}

		database.DB.Exec(
			`UPDATE users SET password_hash=$1, updated_at=NOW() WHERE id=$2`,
			hash, req.UserID,
		)
	}

	_, err := database.DB.Exec(`
		UPDATE users SET
			email=COALESCE(NULLIF($1,''), email),
			name=COALESCE(NULLIF($2,''), name),
			employee_id=COALESCE(NULLIF($3,''), employee_id),
			employee_name=COALESCE(NULLIF($2,''), employee_name),
			phone_number=COALESCE(NULLIF($4,''), phone_number),
			type_of_clearance=COALESCE(NULLIF($5,''), type_of_clearance),
			position_level=COALESCE(NULLIF($6,''), position_level),
			designation=COALESCE(NULLIF($7,''), designation),
			current_location=COALESCE(NULLIF($8,''), current_location),
			date_of_hired=CASE WHEN $9='' THEN date_of_hired ELSE $9::date END,
			date_of_clearance=CASE WHEN $10='' THEN date_of_clearance ELSE $10::date END,
			clearance_area=COALESCE(NULLIF($11,''), clearance_area),
			updated_at=NOW()
		WHERE id=$12`,
		req.Email,
		req.EmployeeName,
		req.EmployeeID,
		req.PhoneNumber,
		req.TypeOfClearance,
		req.PositionLevel,
		req.Designation,
		req.CurrentLocation,
		req.DateOfHired,
		req.DateOfClearance,
		req.ClearanceArea,
		req.UserID,
	)

	if err != nil {
		log.Println("❌ UpdateEmployeeByAdmin SQL error:", err)
		http.Error(w, "Failed to update employee", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Employee updated successfully",
	})
}

/* ================== ADMIN: DELETE EMPLOYEE ================== */

func DeleteEmployee(w http.ResponseWriter, r *http.Request) {

	email := r.Header.Get("X-User-Email")
	role, _ := getUserRole(email)

	if role != "admin" {
		http.Error(w, "Forbidden: Admin access required", http.StatusForbidden)
		return
	}

	var req struct {
		UserID int `json:"user_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var targetRole string
	database.DB.QueryRow(`SELECT role FROM users WHERE id=$1`, req.UserID).Scan(&targetRole)

	if targetRole == "admin" {
		http.Error(w, "Cannot delete admin users", http.StatusForbidden)
		return
	}

	_, err := database.DB.Exec(`DELETE FROM users WHERE id=$1`, req.UserID)
	if err != nil {
		http.Error(w, "Failed to delete employee", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Employee deleted successfully",
	})
}
