package runningNumberRepository

import (
	"context"

	"go.mongodb.org/mongo-driver/mongo"
)

type Repository struct {
	MongoDB *mongo.Database
	Context context.Context
}

func NewRepository(ctx context.Context, MongoDB *mongo.Database) Repository {
	return Repository{
		Context: ctx,
		MongoDB: MongoDB,
	}
}
