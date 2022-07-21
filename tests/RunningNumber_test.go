package mkpmobileutilstest

import (
	"fmt"
	"testing"
	"time"

	mkpmobileutils "github.com/dandeat/mkpmobile-utils/src/utils"
)

//go test -v -run=TestRunningNumber
func TestRunningNumber(t *testing.T) {

	var timNow = time.Now()

	dbTimeDateNow := timNow.Format("060102")
	dataType := "BIL-" + dbTimeDateNow
	autoNumb, err := runningNumberRepo.RunningNumberValueWithDatatype(dataType, "", 7)
	if err != nil {
		fmt.Println("Error Running Number ", err.Error())
		return
	}
	transactionNumber := dataType + "-" + autoNumb

	fmt.Println(transactionNumber)
}

func TestRandNumber(t *testing.T) {
	fmt.Println(mkpmobileutils.RandNumber(9))
}
