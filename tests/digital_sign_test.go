package mkpmobileutilstest

import (
	"fmt"
	"testing"

	mkpmobileutils "github.com/dandeat/mkpmobile-utils/src/utils"
)

type DummyBodyRequest struct {
	GrantType      string `json:"grantType"`
	AdditionalInfo string `json:"additionalInfo"`
}

func TestCreateDigitalSignature(t *testing.T) {
	reqBody := mkpmobileutils.DigitalSignature{
		HttpMethod:  "POST",
		EndpointUrl: "/bi-fast/transfer-interbank",
		AccessToken: "qKtd8sRfA1ChyKYSYQzOBWg7u7LyIqaghvVWZhfnG3AvKAQredQBJg",
		RequestBody: DummyBodyRequest{
			GrantType:      "client_credentials",
			AdditionalInfo: mkpmobileutils.EMPTY_VALUE,
		},
		Timestamp: mkpmobileutils.Timestamp(),
	}

	scretKey := "9fd19a1a-2081-475f-bbe4-064c2702fb13"

	signature, err := mkpmobileutils.CreateDigitalSignature(reqBody, scretKey)
	if err != nil {
		fmt.Println("err ", err)
	}

	fmt.Println("Before :> ", reqBody)
	fmt.Println("After  :> ", signature)
}
