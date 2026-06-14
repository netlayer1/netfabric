# Network AI Orchestrator

AI-powered network management platform for MSPs and network engineers. Connect to your Cisco (and other) devices over SSH, run AI-driven analysis using Claude, and manage configurations — all from a single web UI.

## Features

- **Device management** — add and manage network devices with encrypted credential storage
- **SSH connectivity** — connects via Netmiko/Paramiko, supports legacy SHA1 KEX for older devices
- **AI analysis** — powered by Anthropic Claude; runs BGP, config review, log analysis, and status checks
- **Config snapshots & diffs** — track configuration changes over time
- **JWT authentication** — secure multi-user access
- **REST API** — full OpenAPI docs at `/docs`

## Tech Stack

- **Backend**: FastAPI, SQLAlchemy, SQLite
- **Auth**: JWT (python-jose) + Fernet encryption for device passwords
- **Network**: Netmiko, NAPALM, Paramiko
- **AI**: Anthropic Claude API
- **Frontend**: Vanilla HTML/JS (`frontend/index.html`)

## Getting Started

### Prerequisites

- Python 3.9+
- A virtual environment (recommended)

### Installation

```bash
git clone https://github.com/yourusername/network-ai-orchestrator.git
cd network-ai-orchestrator

python3.9 -m venv venv
source venv/bin/activate

pip install -r requirements.txt
```

### Configuration

```bash
cp .env.example .env
```

Edit `.env` and fill in:

| Variable | Description |
|----------|-------------|
| `ANTHROPIC_API_KEY` | Get from [console.anthropic.com](https://console.anthropic.com) |
| `SECRET_KEY` | JWT secret — run `openssl rand -hex 32` |
| `FERNET_KEY` | Device password encryption key — see `.env.example` for generation command |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Session length (default: 480) |

### Run

```bash
source venv/bin/activate
python -m uvicorn backend.main:app --reload --port 8001
```

Open [http://localhost:8001](http://localhost:8001) for the UI, or [http://localhost:8001/docs](http://localhost:8001/docs) for the API explorer.

## API Overview

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/register` | Create account |
| POST | `/api/auth/login` | Get JWT token |
| GET | `/api/devices` | List devices |
| POST | `/api/devices` | Add device |
| POST | `/api/devices/{id}/test` | Test SSH connectivity |
| GET | `/api/devices/{id}/status` | Pull live device status |
| POST | `/api/analysis` | Run AI analysis |
| GET | `/api/analysis/history` | Analysis history |

## Docker

```bash
docker-compose up --build
```

## Security Notes

- Device passwords are encrypted at rest using Fernet symmetric encryption
- Never commit `.env` or `*.db` files — both are in `.gitignore`
- Set `allow_origins` in `main.py` to your domain before deploying to production

## License

Proprietary — © 2026 Access4. All rights reserved. See [LICENSE](LICENSE).
