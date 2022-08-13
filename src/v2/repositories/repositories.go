package repositories

import (
	"context"
	"database/sql"

	"github.com/streadway/amqp"
	"go.mongodb.org/mongo-driver/mongo"
)

type Repository struct {
	DB      *sql.DB
	MongoDB *mongo.Database
	Context context.Context
	RbtConn *amqp.Connection
}

func NewRepository(
	conn *sql.DB,
	ctx context.Context,
	MongoDB *mongo.Database,
	RbtConn *amqp.Connection,
) Repository {
	return Repository{
		DB:      conn,
		Context: ctx,
		MongoDB: MongoDB,
		RbtConn: RbtConn,
	}
}
