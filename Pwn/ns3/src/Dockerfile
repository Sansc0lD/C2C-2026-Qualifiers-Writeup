FROM alpine:latest

WORKDIR /app

COPY --chmod=755 server .
COPY --chmod=750 run.sh .

CMD ["sh", "./run.sh"]
