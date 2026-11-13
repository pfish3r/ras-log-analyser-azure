# RAS Log Analyser for Azure Linux VMs

Container deployment of the upload-only [RAS Log Analyser](https://github.com/pfish3r/ras-log-analyser), based on v1.1.0. Supports Ubuntu Server 24.04/22.04 and Debian 12/13 with systemd. The VM needs outbound access to GitHub, Docker Hub, PyPI and the OS package repositories.

## Install on your VM

Run these commands in your SSH session. The installer sets up Docker and Compose as needed, checks out the project in /opt/ras-log-analyser-azure, builds the image and waits for the service to become healthy.

```bash
curl -fL https://raw.githubusercontent.com/pfish3r/ras-log-analyser-azure/main/install-azure.sh -o install-azure.sh &&
sudo bash install-azure.sh --lan
```

The --lan option publishes port **8768** on all IPv4 interfaces. Open **http://VM_PRIVATE_IP:8768** over your private network or VPN. The analyser has no login. Restrict Azure NSG inbound TCP 8768 to your trusted client or VPN subnet. The installer leaves Azure networking to the operator.

For SSH-only access use --local. From your client, run `ssh -N -L 8768:127.0.0.1:8768 USER@VM` and open http://127.0.0.1:8768. A fresh installation with no option defaults to loopback.

## Update and data

Run the two installation commands again, omitting --lan to retain the existing bind address. Updates back up a running analyser before building and wait for the replacement container's health check. The checkout, container project and image use the name ras-log-analyser-azure. Its named volume **ras-log-analyser-azure-data** keeps the SQLite issue library and parsing settings. A new volume starts empty. See [container operations](CONTAINERS.md) for importing an existing library, backup and restore. Use normal `docker compose down` to retain the volume.

```bash
cd /opt/ras-log-analyser-azure
sudo docker compose ps
sudo docker compose logs --tail=50
sudo docker compose exec -T analyser python container_backup.py
```

Docker prerequisite references: [Ubuntu](https://docs.docker.com/engine/install/ubuntu/) and [Debian](https://docs.docker.com/engine/install/debian/).
