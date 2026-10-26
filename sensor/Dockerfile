FROM python:3.12-slim
WORKDIR /sensor
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir scapy==2.6.1
COPY nmap_sensor.py .
CMD ["python", "nmap_sensor.py"]
