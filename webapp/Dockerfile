FROM python:3.12-slim

WORKDIR /app
RUN pip install poetry && poetry config virtualenvs.create false
COPY pyproject.toml .
RUN poetry install --no-root
COPY README.md .
COPY templates templates 
COPY settings.py .
COPY webapp.py .
COPY config.toml .


CMD ["python", "webapp.py"]