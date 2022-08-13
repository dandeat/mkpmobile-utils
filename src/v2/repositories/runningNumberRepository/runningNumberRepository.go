package runningNumberRepository

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/dandeat/mkpmobile-utils/src/v2/repositories"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type runningNumberValue struct {
	Prefix      string `json:"prefix"`
	DataType    string `json:"dataType"`
	SeqValue    int    `json:"seqValue"`
	LeadingZero int    `json:"leadingZero"`
}

type runningNumberRepository struct {
	RepoDB repositories.Repository
}

func NewRunningNumberRepository(repoDB repositories.Repository) runningNumberRepository {
	return runningNumberRepository{
		RepoDB: repoDB,
	}
}

type RunningNumberRepository interface {
	GenerateRunningNumber(p string, v string) (string, error)
	RunningNumberValue(prefix string, leadingZero ...int) (string, error)
	RunningNumberValueWithDatatype(datatype string, prefix string, leadingZero ...int) (string, error)
}

func (ctx runningNumberRepository) GenerateRunningNumber(p string, v string) (string, error) {
	var runningNumber string

	err := ctx.RepoDB.DB.QueryRow("SELECT fs_gen_autonum($1, $2)", p, v).Scan(&runningNumber)
	if err != nil {
		return "", err
	}

	return runningNumber, nil
}

func (ctx runningNumberRepository) RunningNumberValue(prefix string, leadingZero ...int) (string, error) {
	colName := "autonumber_col"
	zeroPadding := 0

	if len(leadingZero) > 0 {
		zeroPadding = leadingZero[0]
	}

	filter := bson.M{"prefix": prefix}
	update := bson.M{
		"$set": bson.M{"leadingzero": zeroPadding},
		"$inc": bson.M{"seqvalue": 1},
	}

	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}

	out := ctx.RepoDB.MongoDB.Collection(colName).FindOneAndUpdate(ctx.RepoDB.Context, filter, update, &opt)
	if out.Err() != nil {
		return "", out.Err()
	}

	var runningNumber runningNumberValue
	err := out.Decode(&runningNumber)
	if err != nil {
		return "", err
	}

	runningNumberNo := ""
	if zeroPadding != 0 {
		lpad := leftPad(strconv.Itoa(runningNumber.SeqValue), "0", runningNumber.LeadingZero)
		runningNumberNo = fmt.Sprintf("%s%s", prefix, lpad)
	} else {
		runningNumberNo = fmt.Sprintf("%s%s", prefix, strconv.Itoa(runningNumber.SeqValue))
	}

	return runningNumberNo, nil
}

// func (ctx runningNumberRepository) RunningNumberValueWithDatatype(datatype string, prefix string, leadingZero int) (string, error) {
// 	fmt.Println("Call RunningNumberValueWithDatatype")
// 	return "haha", nil
// }

func (ctx runningNumberRepository) RunningNumberValueWithDatatype(datatype string, prefix string, leadingZero ...int) (string, error) {
	colName := "autonumber_col"
	zeroPadding := 0

	if len(leadingZero) > 0 {
		zeroPadding = leadingZero[0]
	}

	filter := bson.M{"prefix": prefix, "datatype": datatype}
	update := bson.M{
		"$set": bson.M{"leadingzero": zeroPadding},
		"$inc": bson.M{"seqvalue": 1},
	}

	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}

	out := ctx.RepoDB.MongoDB.Collection(colName).FindOneAndUpdate(ctx.RepoDB.Context, filter, update, &opt)
	if out.Err() != nil {
		return "", out.Err()
	}

	var runningNumber runningNumberValue
	err := out.Decode(&runningNumber)
	if err != nil {
		return "", err
	}

	runningNumberNo := ""
	if zeroPadding != 0 {
		iSeq, _ := strconv.ParseInt(strconv.Itoa(runningNumber.SeqValue), 10, 64)
		lpad := padLeft(iSeq, runningNumber.LeadingZero)
		runningNumberNo = fmt.Sprintf("%s%s", prefix, lpad)
	} else {
		runningNumberNo = fmt.Sprintf("%s%s", prefix, strconv.Itoa(runningNumber.SeqValue))
	}

	return runningNumberNo, nil
}

func leftPad(s string, padStr string, pLen int) string {
	return strings.Repeat(padStr, pLen) + s
}

func padLeft(v int64, length int) string {
	abs := math.Abs(float64(v))
	var padding int
	if v != 0 {
		min := math.Pow10(length - 1)

		if min-abs > 0 {
			l := math.Log10(abs)
			if l == float64(int64(l)) {
				l++
			}
			padding = length - int(math.Ceil(l))
		}
	} else {
		padding = length - 1
	}
	builder := strings.Builder{}
	if v < 0 {
		length = length + 1
	}
	builder.Grow(length * 4)
	if v < 0 {
		builder.WriteRune('-')
	}
	for i := 0; i < padding; i++ {
		builder.WriteRune('0')
	}
	builder.WriteString(strconv.FormatInt(int64(abs), 10))
	return builder.String()
}
