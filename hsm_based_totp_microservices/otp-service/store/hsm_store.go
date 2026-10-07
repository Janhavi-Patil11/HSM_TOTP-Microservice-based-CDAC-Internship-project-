package store

import (
	"encoding/binary"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/miekg/pkcs11"
)

var (
	p     *pkcs11.Ctx
	mutex sync.Mutex
)

//
// ============================================================
// INIT HSM CONTEXT (ONLY ONCE AT STARTUP)
// ============================================================
//

func InitHSM() error {

	module := os.Getenv("HSM_MODULE")
	if module == "" {
		return fmt.Errorf("HSM_MODULE missing")
	}

	p = pkcs11.New(module)
	if p == nil {
		return fmt.Errorf("failed to load HSM module")
	}

	if err := p.Initialize(); err != nil {
		return fmt.Errorf("HSM initialize failed: %v", err)
	}

	fmt.Println("✅ HSM context initialized successfully")
	return nil
}

//
// ============================================================
// OPEN NEW SESSION (PER OPERATION)
// ============================================================
//

func openSession() (pkcs11.SessionHandle, error) {

	slots, err := p.GetSlotList(true)
	if err != nil || len(slots) == 0 {
		return 0, fmt.Errorf("no HSM slots found")
	}

	var selectedSlot uint

	for _, slot := range slots {
		info, err := p.GetTokenInfo(slot)
		if err != nil {
			continue
		}
		if info.Flags&pkcs11.CKF_TOKEN_INITIALIZED != 0 {
			selectedSlot = slot
			break
		}
	}

	if selectedSlot == 0 {
		return 0, fmt.Errorf("no initialized HSM token found")
	}

	session, err := p.OpenSession(
		selectedSlot,
		pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION,
	)
	if err != nil {
		return 0, err
	}

	pin := os.Getenv("HSM_PIN")
	if err := p.Login(session, pkcs11.CKU_USER, pin); err != nil {
		p.CloseSession(session)
		return 0, err
	}

	return session, nil
}

//
// ============================================================
// CREATE SECRET KEY (STORED INSIDE HSM)
// ============================================================
//

func CreateHSMKey(label string) error {

	mutex.Lock()
	defer mutex.Unlock()

	session, err := openSession()
	if err != nil {
		return err
	}
	defer p.CloseSession(session)

	exists, err := keyExists(session, label)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}

	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_GENERIC_SECRET),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 20),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true), // 🔥 Persistent key
	}

	mech := []*pkcs11.Mechanism{
		pkcs11.NewMechanism(pkcs11.CKM_GENERIC_SECRET_KEY_GEN, nil),
	}

	_, err = p.GenerateKey(session, mech, template)
	if err != nil {
		return fmt.Errorf("HSM key generation failed: %v", err)
	}

	return nil
}

//
// ============================================================
// GENERATE OTP (TIME BASED)
// ============================================================
//

func GenerateOTP(label string) (string, error) {
	counter := uint64(time.Now().Unix() / 60)
	return GenerateOTPWithCounter(label, counter)
}

func GenerateOTPWithCounter(label string, counter uint64) (string, error) {

	mutex.Lock()
	defer mutex.Unlock()

	session, err := openSession()
	if err != nil {
		return "", err
	}
	defer p.CloseSession(session)

	key, err := findKey(session, label)
	if err != nil {
		return "", err
	}

	counterBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(counterBytes, counter)

	err = p.SignInit(session,
		[]*pkcs11.Mechanism{
			pkcs11.NewMechanism(pkcs11.CKM_SHA_1_HMAC, nil),
		}, key)
	if err != nil {
		return "", fmt.Errorf("SignInit failed: %v", err)
	}

	hmac, err := p.Sign(session, counterBytes)
	if err != nil {
		return "", fmt.Errorf("Sign failed: %v", err)
	}

	offset := hmac[len(hmac)-1] & 0x0F
	binaryCode := (int(hmac[offset])&0x7f)<<24 |
		(int(hmac[offset+1])&0xff)<<16 |
		(int(hmac[offset+2])&0xff)<<8 |
		(int(hmac[offset+3]) & 0xff)

	otp := binaryCode % 1000000

	return fmt.Sprintf("%06d", otp), nil
}

//
// ============================================================
// DELETE SECRET AFTER SUCCESSFUL VERIFICATION
// ============================================================
//

func DeleteKey(label string) error {

	mutex.Lock()
	defer mutex.Unlock()

	session, err := openSession()
	if err != nil {
		return err
	}
	defer p.CloseSession(session)

	key, err := findKey(session, label)
	if err != nil {
		return err
	}

	return p.DestroyObject(session, key)
}

//
// ============================================================
// FIND SECRET KEY
// ============================================================
//

func findKey(session pkcs11.SessionHandle, label string) (pkcs11.ObjectHandle, error) {

	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}

	if err := p.FindObjectsInit(session, template); err != nil {
		return 0, err
	}

	objs, _, err := p.FindObjects(session, 1)
	p.FindObjectsFinal(session)

	if err != nil {
		return 0, err
	}

	if len(objs) == 0 {
		return 0, fmt.Errorf("HSM key not found")
	}

	return objs[0], nil
}

func keyExists(session pkcs11.SessionHandle, label string) (bool, error) {

	_, err := findKey(session, label)
	if err != nil {
		if err.Error() == "HSM key not found" {
			return false, nil
		}
		return false, err
	}

	return true, nil
}
