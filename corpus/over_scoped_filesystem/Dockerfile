FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY server.py .
COPY sandbox_fs ./sandbox_fs

EXPOSE 8000

CMD ["python", "server.py"]