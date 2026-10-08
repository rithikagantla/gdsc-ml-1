# OWNER: Ankitha · WEEK 2–4
# One image runs any corpus server: `docker run ... python servers/<name>/server.py`
FROM python:3.12-slim
WORKDIR /corpus
RUN pip install --no-cache-dir "mcp[cli]>=2,<3"
COPY servers/ servers/
# Default: the clean baseline. docker-compose overrides `command` per server.
CMD ["python", "servers/00_hello/server.py"]
