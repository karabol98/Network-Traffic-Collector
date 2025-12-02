FROM python:3.12-slim

WORKDIR /app
RUN pip install poetry && poetry config virtualenvs.create false
COPY pyproject.toml .
RUN poetry install --no-root
COPY README.md .
COPY settings.py .
COPY templates ./templates
COPY static ./static
COPY app.py .
COPY config.toml .


CMD ["python", "app.py"]