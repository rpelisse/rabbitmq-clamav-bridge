##!/usr/bin/env python3
"""
rabbitmq-clamav-bridge

Consumes messages from the 'quarantine' queue, scans the message body
(or a referenced payload) with ClamAV via clamd, and routes the message
to 'released' or 'rejected' queues, depending on the scan result.
"""

import os
import sys
import io
import logging
import pika
import clamd

# ---------------------------------------------------------------------------
# Configuration (via environment variables, so it's Helm/K8s-friendly)
# ---------------------------------------------------------------------------

RABBITMQ_HOST = os.getenv("RABBITMQ_HOST", "localhost")
RABBITMQ_PORT = int(os.getenv("RABBITMQ_PORT", "5672"))
RABBITMQ_USER = os.getenv("RABBITMQ_USER", "")
RABBITMQ_PASSWORD = os.getenv("RABBITMQ_PASSWORD", "")
RABBITMQ_VHOST = os.getenv("RABBITMQ_VHOST", "/")

QUEUE_UNVERIFIED = os.getenv("QUEUE_UNVERIFIED", "unverified")
QUEUE_VERIFIED = os.getenv("QUEUE_VERIFIED", "verified")
QUEUE_QUARANTINE = os.getenv("QUEUE_QUARANTINE", "quarantine")

CLAMD_HOST = os.getenv("CLAMD_HOST", "localhost")
CLAMD_PORT = int(os.getenv("CLAMD_PORT", "3310"))
CLAMD_USE_UNIX_SOCKET = os.getenv("CLAMD_USE_UNIX_SOCKET", "false").lower() == "true"
CLAMD_UNIX_SOCKET_PATH = os.getenv("CLAMD_UNIX_SOCKET_PATH", "/var/run/clamav/clamd.ctl")

PREFETCH_COUNT = int(os.getenv("PREFETCH_COUNT", "10"))

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("rabbitmq-clamav-bridge")

# ---------------------------------------------------------------------------
# ClamAV client
# ---------------------------------------------------------------------------

def build_clamd_client():
    """Create and verify a connection to clamd."""
    if CLAMD_USE_UNIX_SOCKET:
        cd = clamd.ClamdUnixSocket(path=CLAMD_UNIX_SOCKET_PATH)
    else:
        cd = clamd.ClamdNetworkSocket(host=CLAMD_HOST, port=CLAMD_PORT)

    try:
        cd.ping()
        log.info("Connected to clamd successfully.")
    except clamd.ConnectionError as e:
        log.error("Could not connect to clamd: %s", e)
        raise

    return cd

def scan_bytes(cd, payload: bytes) -> bool:
    """
    Scan a byte payload using clamd's INSTREAM command.
    Returns True if clean, False if infected.
    """
    result = cd.instream(io.BytesIO(payload))
    # result looks like: {'stream': ('OK', None)} or {'stream': ('FOUND', 'Eicar-Test-Signature')}
    status, signature = result["stream"]

    if status == "OK":
        return True
    elif status == "FOUND":
        log.warning("Infected payload detected: %s", signature)
        return False
    else:
        # Treat anything unexpected as suspicious rather than silently passing it through
        log.error("Unexpected clamd response: %s", result)
        return False

# ---------------------------------------------------------------------------
# RabbitMQ handling
# ---------------------------------------------------------------------------

def build_connection() -> pika.BlockingConnection:
    credentials = pika.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASSWORD)
    parameters = pika.ConnectionParameters(
        host=RABBITMQ_HOST,
        port=RABBITMQ_PORT,
        virtual_host=RABBITMQ_VHOST,
        credentials=credentials,
        heartbeat=30,
        blocked_connection_timeout=60,
    )
    return pika.BlockingConnection(parameters)


def declare_queues(channel):
    """Make sure all three queues exist (idempotent)."""
    for q in (QUEUE_UNVERIFIED, QUEUE_VERIFIED, QUEUE_QUARANTINE):
        channel.queue_declare(queue=q, durable=True)


def main():
    cd = build_clamd_client()

    connection = build_connection()
    channel = connection.channel()
    declare_queues(channel)
    channel.basic_qos(prefetch_count=PREFETCH_COUNT)

    def on_message(ch, method, properties, body: bytes):
        try:
            is_clean = scan_bytes(cd, body)
        except Exception:
            log.exception("Scan failed; requeueing message for retry.")
            # nack without requeue=False -> message goes back to the queue
            ch.basic_nack(delivery_tag=method.delivery_tag, requeue=True)
            return

        target_queue = QUEUE_VERIFIED if is_clean else QUEUE_QUARANTINE

        ch.basic_publish(
            exchange="",
            routing_key=target_queue,
            body=body,
            properties=pika.BasicProperties(
                delivery_mode=2,  # persistent
                content_type=properties.content_type,
                headers=properties.headers,
            ),
        )

        log.info(
            "Message routed to '%s' (clean=%s, size=%d bytes)",
            target_queue, is_clean, len(body),
        )

        ch.basic_ack(delivery_tag=method.delivery_tag)

    channel.basic_consume(queue=QUEUE_UNVERIFIED, on_message_callback=on_message)

    log.info("Bridge started. Waiting for messages on '%s'...", QUEUE_UNVERIFIED)
    try:
        channel.start_consuming()
    except KeyboardInterrupt:
        log.info("Shutting down gracefully.")
        channel.stop_consuming()
    finally:
        connection.close()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        log.exception("Fatal error in bridge.")
        sys.exit(1)
