package services

import (
	"fmt"
	"log"
	"sync"
	"time"

	"otp-service/store"
	"otp-service/utils"
)

// otpTimestamps stores the exact Unix timestamp when each OTP was generated.
// This is critical: we need to verify against the SAME counter that was used
// during generation, not the current time (which may have crossed a minute boundary).
var (
	otpTimestamps   = make(map[string]int64)
	otpTimestampsMu sync.RWMutex
)

//
// ============================================================
// GENERATE AND SEND OTP
// ============================================================
//

func GenerateAndSendOTP(email string) (string, int64, error) {

	// Step 1: Generate unique OTP ID
	otpID := utils.GenerateOTPID()

	// Step 2: Create secret inside HSM
	if err := store.CreateHSMKey(otpID); err != nil {
		return "", 0, err
	}

	// Step 3: Record exact generation time BEFORE generating OTP
	generatedAt := time.Now().Unix()
	counter := uint64(generatedAt / 60)

	log.Printf("🔑 OTP Generate: otpID=%s, counter=%d, generatedAt=%d", otpID, counter, generatedAt)

	// Step 4: Generate TOTP using HSM with that exact counter
	otp, err := store.GenerateOTPWithCounter(otpID, counter)
	if err != nil {
		_ = store.DeleteKey(otpID)
		return "", 0, err
	}

	// Step 5: Store the generation timestamp BEFORE sending email
	// (email sending can take 10-20 seconds)
	otpTimestampsMu.Lock()
	otpTimestamps[otpID] = generatedAt
	otpTimestampsMu.Unlock()

	// Step 6: Send OTP to user via email
	if err := SendOTPEmailNotification(email, otpID, otp); err != nil {
		// Clean up on failure
		_ = store.DeleteKey(otpID)
		otpTimestampsMu.Lock()
		delete(otpTimestamps, otpID)
		otpTimestampsMu.Unlock()
		return "", 0, fmt.Errorf("failed to send OTP email: %w", err)
	}

	// Step 7: Calculate remaining seconds (OTP valid for 120 seconds from generation)
	elapsed := time.Now().Unix() - generatedAt
	remaining := int64(120) - elapsed
	if remaining < 0 {
		remaining = 0
	}

	log.Printf("✅ OTP sent: otpID=%s, remaining=%ds", otpID, remaining)

	return otpID, remaining, nil
}

//
// ============================================================
// VERIFY STORED OTP
// ============================================================
//

func VerifyStoredOTP(otpID string, userOTP string) (bool, error) {

	// Get the original generation timestamp
	otpTimestampsMu.RLock()
	generatedAt, exists := otpTimestamps[otpID]
	otpTimestampsMu.RUnlock()

	var baseCounter uint64

	if exists {
		// Use the counter from when OTP was actually generated
		baseCounter = uint64(generatedAt / 60)

		// Check if OTP has expired (120 second window)
		elapsed := time.Now().Unix() - generatedAt
		log.Printf("🔍 OTP Verify: otpID=%s, baseCounter=%d, elapsed=%ds", otpID, baseCounter, elapsed)

		if elapsed > 120 {
			log.Printf("⏰ OTP expired: otpID=%s, elapsed=%ds > 120s", otpID, elapsed)
			_ = store.DeleteKey(otpID)
			otpTimestampsMu.Lock()
			delete(otpTimestamps, otpID)
			otpTimestampsMu.Unlock()
			return false, nil
		}
	} else {
		// Fallback: no stored timestamp (e.g., service restarted)
		baseCounter = uint64(time.Now().Unix() / 60)
		log.Printf("⚠️ OTP Verify fallback: otpID=%s, baseCounter=%d (no stored timestamp)", otpID, baseCounter)
	}

	// Check the generation counter and adjacent windows
	// to handle minute-boundary edge cases
	for i := int64(-2); i <= 2; i++ {
		counter := uint64(int64(baseCounter) + i)

		expectedOTP, err := store.GenerateOTPWithCounter(otpID, counter)
		if err != nil {
			if err.Error() == "HSM key not found" {
				log.Printf("❌ HSM key not found: otpID=%s", otpID)
				otpTimestampsMu.Lock()
				delete(otpTimestamps, otpID)
				otpTimestampsMu.Unlock()
				return false, nil
			}
			return false, err
		}

		if expectedOTP == userOTP {
			log.Printf("✅ OTP verified: otpID=%s, counter=%d", otpID, counter)
			_ = store.DeleteKey(otpID)
			otpTimestampsMu.Lock()
			delete(otpTimestamps, otpID)
			otpTimestampsMu.Unlock()
			return true, nil
		}
	}

	log.Printf("❌ OTP mismatch: otpID=%s, none of the counter windows matched", otpID)
	return false, nil
}
