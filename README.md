# Reports to STIX Bundle Generator

Turn cyber threat intelligence reports into **STIX 2.1 bundles** through a web UI, FastAPI backend, and Docker-based deployment.

## What it does

The application processes a report in four stages:

1. **Extractor agent** builds a draft structured representation from the source document.
2. **Verifier agent** removes unsupported items, improves evidence/context, and keeps supported semantic entities.
3. **Relationship builder** adds deterministic relationships after verification.
4. **STIX exporter** serializes the result into a STIX 2.1 JSON bundle.

The web app lets a user upload a report and download the generated STIX bundle.

---

## Demo

<img width="808" height="906" alt="Image" src="https://github.com/user-attachments/assets/89190bf1-4e32-4461-ad5c-168a489c2c18" />

*A quick demonstration of uploading a cyber threat report and generating a valid STIX 2.1 bundle.*

---
## Features

- Extracts:
  - file hashes
  - IPv4 addresses
  - domains
  - malware
  - attack patterns
  - threat actors
  - campaigns
- Filters benign/reference/public-service domains from final indicators
- Adds deterministic relationships after verification
- Exports valid STIX 2.1 JSON bundles
- Supports browser uploads through a single-origin reverse proxy
- Supports Docker Compose deployment
- Supports HTTPS on a public IP using Let's Encrypt IP certificates

---

## Requirements

- Python 3.13+
- `uv`
- Docker + Docker Compose
- Nginx container
- A valid OpenAI API key
- A public IP address if you want Let's Encrypt IP certificates

---

## Environment

Create a `.env` file in the project root:

```env
OPENAI_API_KEY=replace_me
SERVER_IP=replace_with_public_ip
STIX_OUTPUT_DIR=/tmp/stix
```

### Variables

- `OPENAI_API_KEY`  
  Used by the model-backed extraction / verification flow.

- `SERVER_IP`  
  Used by the Nginx config template and certificate paths.

- `STIX_OUTPUT_DIR`  
  Output directory for generated STIX bundles.

---

## Local development

Install dependencies:

```bash
uv sync
```

Run the API locally:

```bash
uv run uvicorn backend.app:app --host 0.0.0.0 --port 8000
```

Run the CLI:

```bash
uv run python -m backend.main convert /path/to/report.pdf --output-name stix_bundle_final.json
```

---

## FastAPI endpoint

### `POST /api/convert`

**Request**
- `multipart/form-data`
- file field name: `file`

**Response**
- generated STIX 2.1 JSON bundle

The frontend uses the same-origin path:

```javascript
fetch('/api/convert', {
  method: 'POST',
  body: formData,
})
```

---

## Docker deployment

Build and start the stack:

```bash
docker compose up -d --build
```

Check status:

```bash
docker compose ps
```

Check logs:

```bash
docker compose logs -f api
docker compose logs -f nginx
```

Open the site:

```text
http://<public-ip>
```

If HTTPS is configured:

```text
https://<public-ip>
```

---

## Docker Compose

A typical Compose setup:

```yaml
version: "3.9"

services:
  api:
    build:
      context: .
      dockerfile: api/Dockerfile
    container_name: stix-api
    restart: unless-stopped
    expose:
      - "8000"
    environment:
      PYTHONPATH: /app/backend
      OPENAI_API_KEY: ${OPENAI_API_KEY}
      STIX_OUTPUT_DIR: ${STIX_OUTPUT_DIR}
    volumes:
      - ./backend:/app/backend:z

  nginx:
    image: nginx:alpine
    container_name: stix-nginx
    restart: unless-stopped
    depends_on:
      - api
    ports:
      - "80:80"
      - "443:443"
    environment:
      SERVER_IP: ${SERVER_IP}
    volumes:
      - ./frontend:/srv:ro,z
      - ./nginx/default.conf.template:/etc/nginx/templates/default.conf.template:ro,z
      - /etc/letsencrypt:/etc/letsencrypt:ro,z
```

If SELinux is enabled on the host, the `:z` suffix is useful for bind mounts.

---

## Let's Encrypt IP certificate

This deployment uses a **Let's Encrypt IP certificate** with Nginx.

### Requirements

- the IP must be public
- port **80** must be reachable from the internet
- port **443** must be reachable from the internet
- Certbot must be recent enough to support IP certificates

### Generate the certificate

Stop Nginx temporarily so Certbot can bind port 80:

```bash
docker compose stop nginx
```

Request a staging certificate first:

```bash
sudo certbot certonly --staging \
  --preferred-profile shortlived \
  --standalone \
  --ip-address "${SERVER_IP}"
```

Then request the real certificate:

```bash
sudo certbot certonly \
  --preferred-profile shortlived \
  --standalone \
  --ip-address "${SERVER_IP}"
```

If you are not exporting `SERVER_IP` in your shell, replace it with the actual public IP when running the command.

Issued files are typically stored at:

```text
/etc/letsencrypt/live/<public-ip>/fullchain.pem
/etc/letsencrypt/live/<public-ip>/privkey.pem
```

After issuance, start the stack again:

```bash
docker compose up -d --build
```

Test HTTPS:

```bash
curl -vk https://<public-ip>
```

---

## Troubleshooting

### Upload returns 404 for `/convert`
The reverse proxy is probably stripping `/api`.

Correct upstream block:

```nginx
location /api/ {
    proxy_pass http://api:8000;
}
```

### Upload fails or resets
Watch both logs while reproducing the problem:

```bash
docker compose logs -f nginx
docker compose logs -f api
```

### Certbot production fails
The most common cause is that port **80** is not reachable from the public internet.

Test from outside:

```bash
curl -v http://<public-ip>/
```

### HTTPS fails after certificate issuance
Check:
- cert files exist at the expected paths
- Nginx rendered the template correctly
- ports 80 and 443 are open
- Nginx config passes validation

```bash
docker compose exec nginx nginx -t
docker compose exec nginx cat /etc/nginx/conf.d/default.conf
```

---

## Recommended workflow

### Production
- use Docker Compose
- terminate TLS with Nginx
- use Let's Encrypt IP certificates if you do not have a domain
- keep port 80 reachable for renewal

---

## Future improvements

- background job queue for long-running reports
- authentication for the upload page
- richer relationship inference
- ATT&CK enrichment
- persistent job history
- health checks and status endpoints
