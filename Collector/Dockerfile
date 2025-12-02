FROM python:3.12-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Εγκατάσταση βασικών εργαλείων
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Εγκατάσταση Litestream
ADD https://github.com/benbjohnson/litestream/releases/download/v0.3.13/litestream-v0.3.13-linux-amd64.deb /tmp/litestream.deb
RUN dpkg -i /tmp/litestream.deb && rm /tmp/litestream.deb

# Εγκατάσταση Poetry
RUN pip install poetry && poetry config virtualenvs.create false

# Εγκατάσταση βασικών βιβλιοθηκών του project
COPY pyproject.toml poetry.lock* ./
RUN poetry install --no-root --no-interaction --no-ansi

# Αντιγραφή όλου του κώδικα (μαζί με τους φακέλους sigma)
COPY . .

# --- FIX: Η Λύση για τα errors ---
# Εγκαθιστούμε τα requirements του φακέλου ΚΑΙ το sigmatools που έλειπε
RUN pip install -r sigma_scheduler/requirements.txt
RUN pip install pyyaml croniter sigmatools

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s \
  CMD curl -f http://localhost:8000/health || exit 1

CMD ["python3", "collector.py"]