package rabbitMqRepository

import (
	"github.com/dandeat/mkpmobile-utils/src/v2/repositories"
	"github.com/streadway/amqp"
)

type RbtSubFilter struct {
	Queue     string
	Consumer  string
	AutoAck   bool
	Exclusive bool
	NoLocal   bool
	NoWait    bool
	Args      amqp.Table
}

type RbtPubFilter struct {
	Exchange  string
	Key       string
	Mandatory bool
	Immediate bool
	Msg       amqp.Publishing
}

type rabbitMqRepository struct {
	RepoDB repositories.Repository
}

func NewRabbitMqRepository(RepoDB repositories.Repository) rabbitMqRepository {
	return rabbitMqRepository{
		RepoDB: RepoDB,
	}
}

type RabbitMqRepository interface {
	BufferMessage(filter RbtSubFilter) (msg <-chan amqp.Delivery, err error)
	PublishMessage(filter RbtPubFilter) error
}

func (repo rabbitMqRepository) BufferMessage(filter RbtSubFilter) (msg <-chan amqp.Delivery, err error) {

	rbtChann, err := repo.RepoDB.RbtConn.Channel()
	if err != nil {
		return msg, err
	}

	msg, err = rbtChann.Consume(
		filter.Queue,     // queue name
		filter.Consumer,  // consumer
		filter.AutoAck,   // auto-ack
		filter.Exclusive, // exclusive
		filter.NoLocal,   // no local
		filter.NoWait,    // no wait
		filter.Args,      // arguments
	)
	if err != nil {
		return msg, err
	}

	return msg, err
}

func (repo rabbitMqRepository) PublishMessage(filter RbtPubFilter) error {

	rbtChann, err := repo.RepoDB.RbtConn.Channel()
	if err != nil {
		return err
	}

	err = rbtChann.Publish(
		filter.Exchange,  //Exchange
		filter.Key,       //Key
		filter.Mandatory, //Mandatory
		filter.Immediate, //Immediate
		filter.Msg,       //Message
	)
	if err != nil {
		return err
	}

	return nil
}
