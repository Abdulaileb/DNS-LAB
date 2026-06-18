FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1

RUN pip install --no-cache-dir dnslib

WORKDIR /app
COPY resolver.py /app/resolver.py

EXPOSE 53/udp
CMD ["python3", "/app/resolver.py"]
