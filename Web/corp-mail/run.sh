#!/bin/sh
rm ./run.sh
# Generate secrets
export JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
export FLAG=${GZCTF_FLAG:-C2C{fakeflag}}

supervisord -c /etc/supervisor/conf.d/supervisord.conf