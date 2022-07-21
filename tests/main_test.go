package mkpmobileutilstest

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	"github.com/dandeat/mkpmobile-utils/src/runningNumberRepository"
	testconfig "github.com/dandeat/mkpmobile-utils/tests/testConfig"
	"go.mongodb.org/mongo-driver/mongo"
)

var (
	db                *sql.DB
	ctx               = context.Background()
	mongoDB           *mongo.Database
	runningNumberRepo runningNumberRepository.RunningNumberRepository
)

func TestMain(t *testing.M) {

	// Database Connection
	if err := testconfig.OpenConnection(); err != nil {
		panic(fmt.Sprintf("Open Connection Faild: %s", err.Error()))
	}
	defer testconfig.CloseConnectionDB()

	// Connection database
	db = testconfig.DBConnection()
	mongoDB = testconfig.ConnectMongo(ctx)
	defer testconfig.CloseMongo(ctx)

	fmt.Println("mongoDB:", mongoDB)

	repoRunningNum := runningNumberRepository.NewRepository(db, ctx, mongoDB)

	runningNumberRepo = runningNumberRepository.NewRunningNumberRepository(repoRunningNum)
	// repoRunningNum := runningNumberRepository.NewRunningNumberRepository(db, ctx, nil)

	// roleRepo = roleRepository.NewRoleRepository(repo)

	t.Run()
}
