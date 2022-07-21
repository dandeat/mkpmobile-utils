package mkpmobileutilstest

import (
	"fmt"
	"io/ioutil"
	"testing"

	mkpmobileutils "github.com/dandeat/mkpmobile-utils/src/utils"
)

func TestCreateTokenSignature(t *testing.T) {
	reqTokenSign := mkpmobileutils.TokenSignature{
		Username:  "1022c0c0-4d9d-42be-ab18-4eab15377a57",
		Timestamp: mkpmobileutils.Timestamp(),
	}

	// Config get RSA Key
	b, err := ioutil.ReadFile("key/rsa_2048_priv.pem") // just pass the file name
	if err != nil {
		fmt.Print("Error : ", err)
	}
	rsaPrivateKey := string(b)
	// End Config get RSA Key

	fmt.Println("Payload :> ", reqTokenSign)
	fmt.Println("RSA Key :> ", rsaPrivateKey)

	signature, err := mkpmobileutils.CreateTokenSignature(reqTokenSign, rsaPrivateKey)
	if err != nil {
		fmt.Println("Error : ", err)
	}
	fmt.Println("Token Signature :> ", signature)
}
