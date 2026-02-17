FROM python:3.11-slim

RUN apt-get update && \
    apt-get install -y haproxy supervisor && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY flask_app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY flask_app/ .
COPY haproxy/haproxy.cfg /etc/haproxy/haproxy.cfg
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY run.sh .
RUN chmod +x run.sh

RUN mkdir -p /app/data

EXPOSE 80

CMD ["/bin/sh", "run.sh"]
