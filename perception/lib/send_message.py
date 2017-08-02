from perception import config
from pika import PlainCredentials, BlockingConnection, ConnectionParameters, BasicProperties, exceptions
import threading
import syslog


class SendToRabbitMQ(object):
    def __init__(self, body, exchange, routing):
        """Send scan message to rabbitMQ"""

        self.body = body
        self.exchange = exchange
        self.routing = routing

        t = threading.Thread(target=self.run)
        t.start()

    def run(self):

        try:
            credentials = PlainCredentials(config.mq_user, config.mq_password)
            connection = BlockingConnection(ConnectionParameters(host=config.mq_host,
                                                                 port=config.mq_port,
                                                                 ssl=config.mq_ssl,
                                                                 credentials=credentials))

            channel = connection.channel()

            channel.basic_publish(exchange=self.exchange,
                                  routing_key=self.routing,
                                  body=self.body,
                                  properties=BasicProperties(
                                      delivery_mode=2
                                  ))
            connection.close()

        except exceptions.ChannelClosed as che:
            syslog.syslog(syslog.LOG_INFO, 'SendToRabbitMQ error: %s' % str(che))
