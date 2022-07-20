package mkpmobileutils

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
	"unicode"

	"github.com/labstack/echo"
)

//Timestamp RFC3339
func Timestamp() string {
	return time.Now().Format(time.RFC3339)
}
func TimetoStr(t time.Time) string {
	return t.Local().String()
}
func TimetoStrFormat(t time.Time, layout string) string {
	return t.Local().Format(layout)
}
func StrToTimeLocal(tm string) (time.Time, error) {
	t, err := time.Parse(LAYOUT_TIMESTAMP, tm)
	if err != nil {
		return time.Now(), err
	}

	return t.Local(), nil
}

//DateTime
func DatetimeNowPgFormat(t time.Time) string {
	return time.Now().Format(LAYOUT_TIMESTAMP)
}
func DatetimeNow() string {
	return time.Now().Format(LAYOUT_DATETIME_STRING)
}
func DateNow() string {
	return time.Now().Format(LAYOUT_DATE)
}
func DatetimeLayoutNow(layout string) string {
	return time.Now().Format(layout)
}

//Masking 12345678 :> *****678
func MaskString(s string) string {
	rs := []rune(s)
	for i := 0; i < len(rs)-4; i++ {
		rs[i] = '*'
	}
	return string(rs)
}

//Bind Validate Struct
func BindValidateStruct(ctx echo.Context, i interface{}) error {
	if err := ctx.Bind(i); err != nil {
		return err
	}

	if err := ctx.Validate(i); err != nil {
		return err
	}
	return nil
}

//Response JSON
func ResponseJSON(success bool, code string, msg string, result interface{}, addMsg ...string) Response {
	tm := time.Now()
	response := Response{
		Meta: Meta{
			Code:          code,
			Success:       success,
			Message:       msg,
			AdditionalMsg: addMsg,
		},
		Result:           result,
		ResponseDatetime: tm,
	}

	return response
}

//Response JSON v1
func ResponseJSONV1(code string, msg string, result interface{}) ResponseV1 {
	tm := time.Now()
	response := ResponseV1{
		Result:           result,
		ResponseCode:     code,
		ResponseMessage:  msg,
		ResponseDatetime: tm,
	}

	return response
}

// Generate Random Number
func RandNumber(max int64) (n int64, err error) {
	nBig, err := rand.Int(rand.Reader, big.NewInt(max))
	if err != nil {
		return n, err
	}
	n = nBig.Int64()
	return n, nil
}

func Int32ToString(n int32) string {
	buf := [11]byte{}
	pos := len(buf)
	i := int64(n)
	signed := i < 0
	if signed {
		i = -i
	}
	for {
		pos--
		buf[pos], i = '0'+byte(i%10), i/10
		if i == 0 {
			if signed {
				pos--
				buf[pos] = '-'
			}
			return string(buf[pos:])
		}
	}
}

// -------------------------------- Digital Signature --------------------------------
func RmSpace(s string) string {
	rr := make([]rune, 0, len(s))
	for _, r := range s {
		if !unicode.IsSpace(r) {
			rr = append(rr, r)
		}
	}
	return string(rr)
}

func CreateDigitalSignature(signaturePayload DigitalSignature, scretKey string) (result string, err error) {

	minifyBody, err := json.Marshal(signaturePayload.RequestBody)
	if err != nil {
		return result, err
	}

	// trimmedBody := RmSpace(string(minifyBody))

	h := sha256.New()
	h.Write([]byte(minifyBody))
	b := h.Sum(nil)

	c := hex.EncodeToString(b)

	lower := strings.ToLower(c)

	strToSign := signaturePayload.HttpMethod +
		":" + signaturePayload.EndpointUrl +
		":" + signaturePayload.AccessToken +
		":" + lower +
		":" + signaturePayload.Timestamp

	sig := hmac.New(sha512.New, []byte(scretKey))
	sig.Write([]byte(strToSign))

	// result := hex.EncodeToString(sig.Sum(nil))
	result = base64.StdEncoding.EncodeToString(sig.Sum(nil))

	return result, err
}

// ------------------------------ End Digital Signature ------------------------------

// --------------------------------- Token Signature ---------------------------------
func CreateTokenSignature(req TokenSignature, keyPath string) (token string, err error) {

	signer, err := loadPrivateKey(keyPath)
	if err != nil {
		return "", err
	}

	stringToSign := req.Username + "|" + req.Timestamp

	token = signer.SHA256withRSA(stringToSign)
	return token, nil
}

func loadPrivateKey(path string) (Signer, error) {
	return parsePrivateKey([]byte(path))
}

func (r *rsaPrivateKey) SHA256withRSA(stringToSign string) string {
	h := sha256.New()
	h.Write([]byte(stringToSign))
	d := h.Sum(nil)
	signature, err := rsa.SignPKCS1v15(rand.Reader, r.PrivateKey, crypto.SHA256, d)
	if err != nil {
		panic(err)
	}
	encodedSig := base64.StdEncoding.EncodeToString(signature)
	return encodedSig
}

func parsePrivateKey(pemBytes []byte) (Signer, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("ssh: no key found")
	}

	var rawkey interface{}
	switch block.Type {
	case "RSA PRIVATE KEY":
		rsa, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rawkey = rsa
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %q", block.Type)
	}
	return newSignerFromKey(rawkey)
}

func newSignerFromKey(k interface{}) (Signer, error) {
	var sshKey Signer
	switch t := k.(type) {
	case *rsa.PrivateKey:
		sshKey = &rsaPrivateKey{t}
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %T", k)
	}
	return sshKey, nil
}

// ------------------------------- End Token Signature -------------------------------

// DB Transactions
func DBTransaction(db *sql.DB, txFunc func(*sql.Tx) error) (err error) {
	tx, err := db.Begin()
	if err != nil {
		return
	}
	defer func() {
		if p := recover(); p != nil {
			tx.Rollback()
			panic(p) // Rollback Panic
		} else if err != nil {
			tx.Rollback() // err is not nill
		} else {
			err = tx.Commit() // err is nil
		}
	}()
	err = txFunc(tx)
	return err
}
