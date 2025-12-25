#!/bin/sh

# Salir inmediatamente si un comando falla (excepto dentro de ifs controlados)
set -e

echo "--- Initializing Scraper Setup ---"

# 1. Asegurar carpeta de datos y SSH
mkdir -p /data /root/.ssh
chmod 700 /root/.ssh

# 2. Descargar el script con reintentos y en modo silencioso
echo "Downloading latest scraper.py..."
wget -q -O /app/scraper.py https://raw.githubusercontent.com/clonikal/laliga-isp-blocks/refs/heads/master/script/scraper.py || { echo "Error: Download failed"; exit 1; }

# 3. Escanear host solo si no está ya en known_hosts
# Nota: Verificamos si la variable ROUTER_IP existe para evitar errores
if [ -n "$ROUTER_IP" ] && ! grep -q "$ROUTER_IP" /root/.ssh/known_hosts 2>/dev/null; then
    echo "Adding $ROUTER_IP to known_hosts..."
    ssh-keyscan -H "$ROUTER_IP" >> /root/.ssh/known_hosts 2>/dev/null
fi

# 4. Bucle infinito con compensación de tiempo (Anti-Drift)
echo "Starting main loop (Target Interval: ${CHECK_INTERVAL}s)..."

# Trap para detener el contenedor limpiamente
trap "echo 'Stopping...'; exit 0" SIGINT SIGTERM

while true; do
    start_time=$(date +%s)
    
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Executing scraper with --openwrt $ROUTER_IP --blocked $EXTRA_PARAMS"
    
    if python3 /app/scraper.py --openwrt "$ROUTER_IP" --blocked $EXTRA_PARAMS; then
        echo "Success."
    else
        echo "Error: Scraper execution failed."
    fi
    
    end_time=$(date +%s)

    duration=$((end_time - start_time))
    
    sleep_time=$((CHECK_INTERVAL - duration))

    if [ "$sleep_time" -le 0 ]; then
        echo "Warning: Task took ${duration}s, which is longer than the interval (${CHECK_INTERVAL}s). Sleeping 0s."
        sleep_time=0
    else
        echo "Task took ${duration}s. Next execution in ${sleep_time}s"
    fi

    sleep "$sleep_time" &
    wait $!
done