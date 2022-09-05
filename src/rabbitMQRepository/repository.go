package rabbitMQRepository

import (
	"context"

	"github.com/streadway/amqp"
)

type Repository struct {
	RMQConn *amqp.Connection
	Context context.Context
}

func NewRepository(ctx context.Context, RMQConn *amqp.Connection) Repository {
	return Repository{
		Context: ctx,
		RMQConn: RMQConn,
	}
}
