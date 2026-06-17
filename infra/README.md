# Infra

Compose stack for the analyst laptop and the deployable Pi 5.

## Services

| Service | Port (localhost only) | Default creds |
|---|---|---|
| TimescaleDB | 5432 | srt / srt_dev_password |
| Grafana | 3000 | admin / admin |
| Mosquitto | 1883 / 9001 | anonymous (lab only) |
| ChirpStack | 8080 | admin / admin (set on first login) |

## Bring up

```bash
docker compose -f infra/docker-compose.yml up -d
docker compose -f infra/docker-compose.yml ps
```

## Tear down + wipe

```bash
docker compose -f infra/docker-compose.yml down
rm -rf infra/volumes
```

## Notes

- All ports are bound to `127.0.0.1` to limit accidental exposure.
- DB schema is applied automatically on first start from
  `infra/timescaledb/init/01_schema.sql`.
- Grafana auto-loads the TimescaleDB datasource and the `overview` dashboard
  from `infra/grafana/provisioning/`.
- ChirpStack is included as a **lab target / replay sink** for LoRaWAN
  scenarios. Disable it on probes that don't need it.
