#!/bin/sh
rm ./run.sh Dockerfile docker-compose.yml
# Generate secrets
export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
export FLAG=${GZCTF_FLAG:-C2C{fakeflag}}

echo $FLAG > /flag.txt

cd /app

python3 generate_keys.py

python3 app.py