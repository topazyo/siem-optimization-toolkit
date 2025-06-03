# src/python/log_router/destinations.py

from typing import Dict, List, Any
import asyncio
import aiohttp
import aioboto3
import azure.functions as func
from azure.storage.blob.aio import BlobServiceClient
from azure.eventhub.aio import EventHubProducerClient
from google.cloud import storage
import json
import logging

class DestinationHandlers:
    """Handlers for various log destinations."""

    def __init__(self, config: Dict):
        """
        Initializes the DestinationHandlers instance.

        This constructor stores the overall configuration, sets up a logger,
        and initializes an `aiohttp.ClientSession` for making HTTP requests
        to various destination APIs.

        Args:
            config (Dict): A dictionary containing overall configuration settings
                           that might be relevant for all destination types,
                           such as global credentials, retry policies, or network settings.
                           Specific destination configurations are passed to each `send_to_*` method.

        Initializes key attributes:
        - `config` (Dict): Stores the provided overall configuration.
        - `logger` (logging.Logger): A configured logger instance.
        - `session` (aiohttp.ClientSession): An asynchronous HTTP client session
                                             used by various handlers. Initialized by
                                             `_initialize_clients`.
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.session = None # Initialized by _initialize_clients
        self._initialize_clients()

    async def _initialize_clients(self):
        """Initialize API clients."""
        self.session = aiohttp.ClientSession()

    async def close(self):
        """
        Cleans up resources, primarily the `aiohttp.ClientSession`.

        This method should be called when the DestinationHandlers instance
        is no longer needed to ensure proper release of network resources.
        """
        if self.session:
            await self.session.close()

    async def send_to_elasticsearch(
        self,
        logs: List[Dict],
        config: Dict
    ) -> bool:
        """
        Asynchronously sends a list of log dictionaries to an Elasticsearch instance.

        Logs are sent using the Elasticsearch Bulk API for efficient ingestion.
        Each log entry is formatted as a JSON document for a specified index.

        Args:
            logs (List[Dict]): A list of dictionaries, where each dictionary
                               represents a log entry to be sent.
            config (Dict): Configuration specific to this Elasticsearch destination.
                           Expected keys:
                           - 'url' (str): The base URL of the Elasticsearch instance
                                          (e.g., "http://localhost:9200").
                           - 'index' (str): The Elasticsearch index where logs should be stored.
                           - Optional: authentication details if required by Elasticsearch.

        Returns:
            bool: True if logs were sent successfully (HTTP 200 or 201 from Bulk API),
                  False otherwise. Errors are logged.
        """
        try:
            url = f"{config['url']}/_bulk"
            bulk_data = []
            
            for log in logs:
                # Prepare bulk format
                bulk_data.extend([
                    json.dumps({"index": {"_index": config['index']}}),
                    json.dumps(log)
                ])
            
            bulk_body = "\n".join(bulk_data) + "\n"
            
            async with self.session.post(
                url,
                data=bulk_body,
                headers={"Content-Type": "application/x-ndjson"}
            ) as response:
                if response.status not in (200, 201):
                    raise Exception(f"Elasticsearch error: {await response.text()}")
                    
            return True
            
        except Exception as e:
            self.logger.error(f"Elasticsearch sending error: {str(e)}")
            return False

    async def send_to_s3(
        self,
        logs: List[Dict],
        config: Dict
    ) -> bool:
        """
        Asynchronously sends a list of log dictionaries to an AWS S3 bucket.

        Logs are typically batched and written as a single JSON object to a
        file in the specified S3 bucket. The filename often includes a timestamp
        and a configured prefix for organization.

        Args:
            logs (List[Dict]): A list of dictionaries, where each dictionary
                               represents a log entry.
            config (Dict): Configuration specific to this S3 destination.
                           Expected keys:
                           - 'bucket' (str): The name of the S3 bucket.
                           - 'prefix' (str): A prefix for the S3 object key (e.g., "logs/app_name/").
                           - Optional: AWS credentials and region if not configured globally.

        Returns:
            bool: True if logs were uploaded successfully, False otherwise.
                  Errors are logged.
        """
        try:
            session = aioboto3.Session()
            async with session.client('s3') as s3:
                # Generate file name
                timestamp = datetime.utcnow().strftime('%Y/%m/%d/%H/%M')
                key = f"{config['prefix']}/{timestamp}.json"
                
                # Upload data
                await s3.put_object(
                    Bucket=config['bucket'],
                    Key=key,
                    Body=json.dumps(logs).encode()
                )
                
            return True
            
        except Exception as e:
            self.logger.error(f"S3 sending error: {str(e)}")
            return False

    async def send_to_splunk(
        self,
        logs: List[Dict],
        config: Dict
    ) -> bool:
        """
        Asynchronously sends a list of log dictionaries to Splunk via its
        HTTP Event Collector (HEC).

        Each log entry is formatted as a Splunk event, including metadata like
        timestamp, host, source, and sourcetype, before being sent.

        Args:
            logs (List[Dict]): A list of dictionaries, where each dictionary
                               represents a log entry.
            config (Dict): Configuration specific to this Splunk HEC destination.
                           Expected keys:
                           - 'url' (str): The URL of the Splunk HEC endpoint
                                          (e.g., "https://splunk.example.com:8088").
                           - 'token' (str): The Splunk HEC authentication token.
                           - 'host' (str, optional): The host value for the events.
                           - 'source' (str, optional): The source value for the events.
                           - 'sourcetype' (str, optional): The sourcetype for the events.

        Returns:
            bool: True if logs were sent successfully (HTTP 200 from HEC),
                  False otherwise. Errors are logged.
        """
        try:
            url = f"{config['url']}/services/collector"
            headers = {
                "Authorization": f"Splunk {config['token']}",
                "Content-Type": "application/json"
            }
            
            # Prepare events
            events = []
            for log in logs:
                events.append({
                    "time": datetime.utcnow().timestamp(),
                    "host": config.get('host', 'sentinel'),
                    "source": config.get('source', 'microsoft_sentinel'),
                    "sourcetype": config.get('sourcetype', '_json'),
                    "event": log
                })
            
            async with self.session.post(
                url,
                json={"events": events},
                headers=headers
            ) as response:
                if response.status != 200:
                    raise Exception(f"Splunk error: {await response.text()}")
                    
            return True
            
        except Exception as e:
            self.logger.error(f"Splunk sending error: {str(e)}")
            return False

    async def send_to_kafka(
        self,
        logs: List[Dict],
        config: Dict
    ) -> bool:
        """
        Asynchronously sends a list of log dictionaries to an Apache Kafka topic.

        Each log entry is typically serialized to JSON and sent as a message
        to the specified Kafka topic. This method handles the producer setup,
        message sending, and producer shutdown.

        Args:
            logs (List[Dict]): A list of dictionaries, where each dictionary
                               represents a log entry.
            config (Dict): Configuration specific to this Kafka destination.
                           Expected keys:
                           - 'bootstrap_servers' (str or List[str]): Kafka broker address(es).
                           - 'topic' (str): The Kafka topic to send logs to.
                           - 'username' (str, optional): Username for SASL authentication.
                           - 'password' (str, optional): Password for SASL authentication.
                           - Other Kafka producer settings as needed by `AIOKafkaProducer`.

        Returns:
            bool: True if all logs were sent successfully, False otherwise.
                  Errors are logged.
        """
        try:
            # Assuming AIOKafkaProducer is available and configured in the environment
            # from aiokafka import AIOKafkaProducer # Would be at the top of the file

            producer_config = {
                'bootstrap_servers': config['bootstrap_servers']
            }
            if 'username' in config and 'password' in config:
                producer_config.update({
                    "security_protocol": "SASL_SSL", # Common, but might vary
                    "sasl_mechanism": "PLAIN",        # Common, but might vary
                    "sasl_plain_username": config['username'],
                    "sasl_plain_password": config['password']
                })
            # Add other relevant Kafka producer settings from config if needed

            producer = AIOKafkaProducer(**producer_config)
            
            await producer.start()
            
            try:
                for log in logs:
                    await producer.send_and_wait(
                        topic=config['topic'],
                        value=json.dumps(log).encode('utf-8') # Ensure encoding
                    )
                return True
            finally:
                await producer.stop()
                
        except Exception as e:
            self.logger.error(f"Kafka sending error: {str(e)}")
            return False