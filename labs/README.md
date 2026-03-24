# GhostGateway Lab Environment

A Docker-based clinical IoT gateway lab for safely testing GhostGateway.

## What's in the Lab

| Container | Role | Port |
|---|---|---|
| `ghostgateway_modbus` | Modbus TCP server (simulated clinical device) | 502 |
| `ghostgateway_mqtt` | Mosquitto MQTT broker (unauthenticated) | 1883 |
| `ghostgateway_clinical` | Clinical gateway simulator (publishes vitals) | - |

## Start the Lab

```bash
cd labs/
docker-compose up -d
```

## Verify Lab is Running

```bash
# Check all containers
docker-compose ps

# Watch live MQTT vitals from the clinical simulator
docker run --rm --network labs_clinical_lab eclipse-mosquitto:2.0 \
  mosquitto_sub -h ghostgateway_mqtt -t "#" -v

# Check Modbus server is up
nc -zv 127.0.0.1 502
```

## Run GhostGateway Against the Lab

```bash
# From project root

# Modbus full recon
python ghostgateway.py --protocol modbus --mode recon --target 127.0.0.1

# MQTT full recon (will discover live clinical topics)
python ghostgateway.py --protocol mqtt --mode recon --broker 127.0.0.1

# Inject malicious commands into the clinical simulator
python ghostgateway.py --protocol mqtt --mode inject --broker 127.0.0.1

# Full attack suite with report
python ghostgateway.py --protocol all --mode full --target 127.0.0.1 --broker 127.0.0.1 --report
```

## Stop the Lab

```bash
docker-compose down
```

## Important

This lab is intentionally misconfigured (no auth, open ports) to simulate
vulnerable clinical IoT environments. **Never expose this lab to any network.**
