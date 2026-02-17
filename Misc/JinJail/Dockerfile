FROM python:3.11-slim

RUN adduser ctf

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && \
    apt-get -y install socat gcc && \
    rm -rf /var/lib/apt/lists/*

COPY app.py requirements.txt ./
COPY flag.txt /root/flag.txt

RUN pip install --no-cache-dir -r requirements.txt

RUN chmod 400 /root/flag.txt && \
    chown root:root /root/flag.txt

RUN chown -R ctf:ctf /app

COPY fix.c /tmp/fix.c
RUN gcc /tmp/fix.c -o /fix
RUN rm /tmp/fix.c
RUN chmod 4755 /fix

EXPOSE 13337

ENTRYPOINT ["socat", "TCP-LISTEN:13337,reuseaddr,fork,nodelay,su=ctf", "EXEC:'timeout 30 python3 app.py'"]
