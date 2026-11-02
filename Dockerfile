FROM python:3.9-slim

WORKDIR /app

COPY agent.py .

ENV PYTHONUNBUFFERED=1

CMD ["python", "-u", "agent.py"]
