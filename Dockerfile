FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

COPY requirements.txt requirements-dashboard.txt ./
ARG WITH_DASHBOARD=1
RUN pip install -r requirements.txt && if [ "$WITH_DASHBOARD" = "1" ]; then pip install -r requirements-dashboard.txt; fi

COPY . .
RUN useradd --create-home --uid 10001 shipguard && mkdir -p /app/data && chown -R shipguard /app/data
USER shipguard

EXPOSE 8088 9000 8101 8102 8502
CMD ["uvicorn", "shipguard.server:create_app", "--factory", "--host", "0.0.0.0", "--port", "8088"]
