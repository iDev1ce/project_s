FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app

COPY pyproject.toml uv.lock README.md /app/

RUN uv sync --frozen --no-dev --no-editable --no-install-project

COPY backend /app/backend

RUN uv sync --frozen --no-dev --no-editable

ENV PYTHONPATH=/app/backend

CMD ["/app/.venv/bin/uvicorn", "project_s.app:app", "--host", "0.0.0.0", "--port", "8000"]
