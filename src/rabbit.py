import datetime
import pika
import asyncio

class Rabbit:
    
    def __init__(self, host, virtual_host, username, password, queues):
        self.connection = pika.BlockingConnection(
            pika.ConnectionParameters(
            host=host, 
            virtual_host=virtual_host, 
            credentials=pika.PlainCredentials(username, password)))
        self.channel = self.connection.channel()
        self._declare_queues(queues)
        self.default_queue = queues[0]
        self.send_message("The service connected to RabbitMQ")

    def _declare_queues(self, queues):
        if not self.channel:
            return
        
        for queue in queues:
            self.channel.queue_declare(queue)

    def send_message(self, message, queue=None):
        asyncio.run(self._send_message(message, queue))

    #sends message throufh default (broadcast) queue and queue passed as parameter 
    async def _send_message(self, message, queue=None):
        if not queue:
            self.channel.basic_publish(exchange='',
                routing_key=self.default_queue,
                body=self._wrap_message(message))
            return

        self.channel.basic_publish(exchange='',
                routing_key=queue,
                body=self._wrap_message(message))

    def _wrap_message(self, message):
        return f"SERVICE | {datetime.datetime.now()} | {message}"