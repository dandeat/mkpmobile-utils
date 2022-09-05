package rabbitMQRepository

import (
	"github.com/streadway/amqp"
)

type rabbitMQRepository struct {
	RepoDB Repository
}

func NewRabbitMQRepository(RepoDB Repository) rabbitMQRepository {
	return rabbitMQRepository{
		RepoDB: RepoDB,
	}
}

func (repo rabbitMQRepository) BufferMessage(
	Queue string,
	Consumer string,
	AutoAck bool,
	Exclusive bool,
	NoLocal bool,
	NoWait bool,
	Args amqp.Table,
) (msg <-chan amqp.Delivery, rbtChann *amqp.Channel, err error) {

	rbtChann, err = repo.RepoDB.RMQConn.Channel()
	if err != nil {
		return msg, rbtChann, err
	}

	_, err = rbtChann.QueueDeclare(
		Queue,
		true,
		false,
		false,
		false,
		nil,
	)
	if err != nil {
		return msg, rbtChann, err
	}

	msg, err = rbtChann.Consume(
		Queue,     // queue name
		Consumer,  // consumer
		AutoAck,   // auto-ack
		Exclusive, // exclusive
		NoLocal,   // no local
		NoWait,    // no wait
		Args,      // arguments
	)
	if err != nil {
		return msg, rbtChann, err
	}

	return msg, rbtChann, err
}

func (repo rabbitMQRepository) PublishMessage(
	Exchange string,
	Key string,
	Mandatory bool,
	Immediate bool,
	Msg amqp.Publishing,
) (rbtChann *amqp.Channel, err error) {

	rbtChann, err = repo.RepoDB.RMQConn.Channel()
	if err != nil {
		return rbtChann, err
	}

	err = rbtChann.Publish(
		Exchange,  //Exchange
		Key,       //Key
		Mandatory, //Mandatory
		Immediate, //Immediate
		Msg,       //Message
	)
	if err != nil {
		return rbtChann, err
	}

	return rbtChann, nil
}
