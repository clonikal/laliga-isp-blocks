# LaLigaGate scraper

Python scripts that generate IP address lists and OpenWrt configurations for
LaLigaGate ISP blocks.

## SSH Key Configuration (Prerequisite)

Since the script uses SSH to connect to the OpenWrt device (especially when running via Docker), the container needs permission to access the router.

1. **Create a folder** to store your keys in the project root:
    ```bash
    mkdir -p id_rsa
    ```
   
2. **Generate a key pair** inside that folder (if you don't have one): Run this command on your PC:
    ```bash
    ssh-keygen -t rsa -f id_rsa/id_rsa -N ""
    ```

    This creates id_rsa (private key) and id_rsa.pub (public key) inside the id_rsa/ folder.

3. **Authorize the key on the router**: Copy the contents of id_rsa/id_rsa.pub and paste them into the /etc/dropbear/authorized_keys file on the router (or /root/.ssh/authorized_keys if you are using OpenSSH).

   Quick command (execute on the router): (Paste the content of your public key into a file or echo it)
    ```bash
    cat id_rsa.pub >> /etc/dropbear/authorized_keys
    ```

## Docker Usage (Recommended)
You can run the scraper in an isolated environment using Docker. This setup automatically handles dependencies and execution via run.sh.

### Start the container
This command will build the image and run the script defined in run.sh.
```bash
docker-compose up --build
```
    
### Stop the container
To stop the execution and remove the created containers and networks:
```bash
docker-compose down
```
    
## Manual Usage (Local Python)
If you prefer to run the Python script directly on your machine without Docker:

### Fetch latest data

```bash
python script/scraper.py
```

### Fetch latest data and update OpenWrt device

Warning: you must use `ssh-copy-id` for the OpenWrt device before running the following command.

```bash
python script/scraper.py -o openwrt.hostname
```

## Data files

| File                          | Description                 |
| ----------------------------- | --------------------------- |
| laliga-ip-list.json           | Local list of blocked IPs.  |
| laliga-openwrt-routes.config  | OpenWrt routes config.      |

## Sources

https://hayahora.futbol/
