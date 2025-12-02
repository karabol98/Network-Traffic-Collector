 Network Traffic Collector & Analyzer

An advanced, containerized network traffic collection system built with Python, Flask, and Redis. designed to capture, analyze, and store network packets in real-time.

 Key Features

Real-time Collection: Efficiently captures network packets via customized collectors.

Data Pipeline: Utilizes Redis for high-performance message queuing and data buffering.

Storage: Persists analyzed data into a local SQLite database (with Litestream support for replication).

Containerized: Fully Dockerized architecture for easy deployment.

REST API: Provides endpoints for health monitoring and data retrieval.

 Architecture

The system consists of the following microservices:

Collector: The core Python application that handles packet ingestion and processing.

Redis: Acts as a broker between the ingestion layer and the storage layer.

Database: SQLite engine for lightweight and fast data persistence.

🏁 Getting Started

Prerequisites

Docker & Docker Compose installed on your machine.

Installation & Running

Clone the repository:

git clone [https://github.com/your-username/network-traffic-collector.git](https://github.com/your-username/network-traffic-collector.git)
cd network-traffic-collector


Start the services:
Run the following command to build and start the containers:

docker-compose up --build -d


Verify installation:
Check the logs to ensure everything is running smoothly:

docker-compose logs -f collector


Access the health endpoint:
http://localhost:8000/health

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

dev_secret

DB_URL

Database connection string

sqlite:////app/data/sigma.db

 Tech Stack

Language: Python 3.11

Framework: Flask

Dependency Management: Poetry

Database: SQLite / Redis

DevOps: Docker, Docker Compose

 Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

 License

This project is licensed under the MIT License - see the LICENSE file for details.