FROM registry.access.redhat.com/ubi9/python-311:1-77.1749486987

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server/ ./server/
COPY static/ ./static/

ENV PYTHONUNBUFFERED=1
ENV ARGUS_GTC_STATIC_DIR=/app/static

EXPOSE 8080

CMD ["uvicorn", "server.main:app", "--host", "0.0.0.0", "--port", "8080"]
