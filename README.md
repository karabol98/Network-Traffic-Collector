📡 Network Traffic Collector & Analyzer

An advanced, containerized network traffic collection system built with Python 3.12, FastAPI, and Redis. Designed to capture, analyze, and store network packets in real-time using Sigma Rules for threat detection.

🚀 Key Features

Real-time Collection: Efficiently captures network packets via customized collectors.

Threat Detection: Integrates Sigma Rules (pySigma, sigmatools) for automated threat analysis.

Data Pipeline: Utilizes Redis for high-performance message queuing and data buffering.

Storage: Persists analyzed data using Litestream for SQLite replication and backup.

Containerized: Fully Dockerized architecture for easy deployment.

REST API: Provides endpoints for health monitoring and data retrieval using FastAPI.

🛠️ Architecture

The system consists of the following microservices:

Collector: The core Python application that handles packet ingestion, rule matching (Sigma), and processing.

Redis: Acts as a broker between the ingestion layer and the storage layer.

Database: SQLite engine for lightweight and fast data persistence.

🏁 Getting Started

Prerequisites

Docker & Docker Compose installed on your machine.

Installation & Running

Clone the repository:

git clone [https://github.com/YOUR_USERNAME/Network-Traffic-Collector.git](https://github.com/YOUR_USERNAME/Network-Traffic-Collector.git)
cd Network-Traffic-Collector


Start the services:
Run the following command to build and start the containers. This will automatically install all dependencies (including pyyaml, croniter, sigmatools).

docker-compose up --build


Verify installation:
Once the logs show Application startup complete, access the health endpoint:

Health Check: http://localhost:8000/health

API Documentation: http://localhost:8000/docs

⚙️ Configuration

You can configure the application via environment variables in docker-compose.yaml:

Variable

Description

Default

REDIS_HOST

Hostname of the Redis service

redis

JWT_SECRET_KEY

Secret key for auth tokens

dev_secret_key

ADMIN_USER_PASSWORD

Default admin password

admin_super_secret_123

DB_URL

Database connection string

sqlite:////app/data/sigma.db

📦 Tech Stack

Language: Python 3.12

Web Framework: FastAPI / Starlette

Dependency Management: Poetry

Analysis Engine: pySigma, sigmatools

Database: SQLite / Redis

DevOps: Docker, Docker Compose

🤝 Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

📄 License

This project is licensed under the MIT License - see the LICENSE file for details.