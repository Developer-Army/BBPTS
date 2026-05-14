# BBPTS API Notes

BBPTS is primarily a CLI-driven reconnaissance pipeline. The local dashboard is intended for viewing state from the SQLite store; it is not a public internet API and should be bound only on trusted interfaces.

## Local Dashboard

Start the dashboard:

```bash
./bbpts -web -port 8080
```

The dashboard reads from the configured state directory and shows scan, target, and event summaries. Treat the dashboard and its backing database as sensitive because they can contain private scope, URLs, vulnerability evidence, screenshots, and API-derived metadata.

## Worker Mesh

Distributed workers communicate over the configured NATS event bus:

```json
{
  "event_bus": {
    "type": "nats",
    "url": "nats://127.0.0.1:4222"
  },
  "fleet": {
    "worker_mesh": true
  }
}
```

Run a worker:

```bash
./bbpts -worker -config configs/config.json
```

Workers subscribe to `job.recon`, execute supported recon tools, publish tool events back to the bus, and send `job.complete` when finished.

## Stability Contract

The internal event schema is:

```json
{
  "target": "https://app.example.com",
  "source": "httpx",
  "type": "service",
  "properties": {
    "status_code": "200"
  }
}
```

Large worker payloads are carried in the event data body, while `properties` is reserved for small metadata.
