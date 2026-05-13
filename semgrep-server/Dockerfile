FROM python:3.12-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends git ca-certificates \
  && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir semgrep

WORKDIR /app

COPY semgrep_server.py /app/semgrep_server.py
COPY http_handler.py /app/http_handler.py
COPY helpers.py /app/helpers.py
COPY run_command.py /app/run_command.py
COPY semgrep_types.py /app/semgrep_types.py

EXPOSE 9091

CMD ["python", "/app/semgrep_server.py"]