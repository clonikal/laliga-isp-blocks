# Usamos Alpine para que la imagen pese muy poco
FROM python:3.11-alpine

# Directorio de trabajo
WORKDIR /app

# Instalamos dependencias de compilación temporalmente y las de ejecución permanentemente
RUN apk add --no-cache openssh-client libffi openssl && \
    apk add --no-cache --virtual .build-deps build-base libffi-dev openssl-dev && \
    pip install --no-cache-dir requests paramiko && \
    apk del .build-deps

# Valor por defecto para el chequeo (600 segundos)
ENV CHECK_INTERVAL=600
ENV EXTRA_PARAMS=""

# Copiar el script de ejecución
COPY run.sh /app/run.sh
RUN chmod +x /app/run.sh

# El comando por defecto al iniciar
CMD ["/app/run.sh"]
