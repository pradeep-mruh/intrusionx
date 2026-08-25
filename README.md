# IntrusionX

An evidence-driven cyber attack investigation and reconstruction platform.

## Philosophy

```
Evidence → Relationships → Reconstruction → Investigation → Human Validation
```

IntrusionX ingests raw security telemetry, normalizes events into a common representation, discovers deterministic relationships between events, reconstructs possible attack sequences, and provides an investigator-facing interface for validation.

All inferences are traceable back to source evidence. No risk scores. No AI chatbots. No fake detections.

---

## Architecture

```
┌────────────────────────────────────────────────────────┐
│                      Frontend (React + Vite)           │
│               Investigation UI / Attack Graph View     │
└────────────────────────┬───────────────────────────────┘
                         │ HTTP / REST
┌────────────────────────▼───────────────────────────────┐
│                   Backend (FastAPI)                    │
│                                                        │
│  ┌──────────┐  ┌─────────────┐  ┌──────────────────┐  │
│  │ Ingestion│→ │Normalization│→ │   Correlation    │  │
│  └──────────┘  └─────────────┘  └────────┬─────────┘  │
│                                           │            │
│                              ┌────────────▼──────────┐ │
│                              │   Reconstruction      │ │
│                              └────────────┬──────────┘ │
│                                           │            │
│                              ┌────────────▼──────────┐ │
│                              │    Investigation      │ │
│                              └───────────────────────┘ │
└────────────────────────┬───────────────────────────────┘
                         │ SQLAlchemy
┌────────────────────────▼───────────────────────────────┐
│                   PostgreSQL                           │
└────────────────────────────────────────────────────────┘
```

### Pipeline stages

| Stage | Responsibility |
|---|---|
| **Ingestion** | Receive raw security evidence (logs, PCAP metadata, EDR events, etc.) |
| **Normalization** | Convert evidence into a common `NormalizedEvent` schema |
| **Correlation** | Discover explainable, rule-based relationships between events |
| **Reconstruction** | Assemble correlated events into candidate attack chains / attack graphs |
| **Investigation** | Investigator operations — confirm, reject, connect, or disconnect relationships |

---

## Technology Stack

| Layer | Technology |
|---|---|
| Frontend | React 18, TypeScript, Vite |
| Backend | Python 3.12, FastAPI, Pydantic v2 |
| Database | PostgreSQL 16 |
| Infrastructure | Docker, Docker Compose |

---

## Repository Structure

```
intrusionx/
├── frontend/          # React + TypeScript + Vite application
├── backend/           # FastAPI application
│   ├── app/
│   │   ├── api/           # HTTP route handlers
│   │   ├── core/          # Configuration, database connection, shared utilities
│   │   ├── models/        # SQLAlchemy ORM models
│   │   ├── schemas/       # Pydantic schemas (request/response shapes)
│   │   ├── services/      # Business logic orchestration
│   │   ├── ingestion/     # Raw evidence intake
│   │   ├── normalization/ # Evidence → NormalizedEvent conversion
│   │   ├── correlation/   # Relationship discovery between events
│   │   ├── reconstruction/# Attack chain assembly
│   │   └── investigation/ # Investigator-facing operations
│   ├── tests/
│   └── requirements.txt
├── data/
│   ├── raw/           # Raw evidence samples (never modified)
│   └── scenarios/     # Named attack scenarios for testing
├── docs/              # Design documents and architecture notes
├── tests/             # Integration and end-to-end tests
├── docker-compose.yml
└── README.md
```

---

## Getting Started

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/) >= 24
- [Docker Compose](https://docs.docker.com/compose/) v2
- [Node.js](https://nodejs.org/) >= 20 (for local frontend development)
- [Python](https://www.python.org/) >= 3.12 (for local backend development)

### Run with Docker Compose (recommended)

```bash
docker compose up --build
```

Services will be available at:

| Service | URL |
|---|---|
| Frontend | http://localhost:5173 |
| Backend API | http://localhost:8000 |
| Backend Docs | http://localhost:8000/docs |
| PostgreSQL | localhost:5432 |

### Local development — Backend

```bash
cd backend

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set environment variables (copy and edit)
cp .env.example .env

# Start the API server (requires a running PostgreSQL instance)
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Local development — Frontend

```bash
cd frontend

npm install
npm run dev
```

### Health checks

```
GET http://localhost:8000/health          # Backend + DB connectivity
GET http://localhost:5173                 # Frontend served by Vite dev server
```

---

## Development Principles

1. All security inferences must be traceable back to source evidence.
2. Original evidence is immutable — never modified after ingestion.
3. Security logic is deterministic and explainable, not probabilistic.
4. Security logic is kept separate from presentation logic.
5. Modules are small and independently testable.
6. Type hints are used throughout all Python code.
7. Clear names are preferred over abbreviations.
