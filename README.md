
# CyberShield v1.0

Plateforme de cybersécurité défensive développée en Python.

## Fonctionnalités

- Analyse antivirus avec ClamAV
- Recherche de vulnérabilités CVE via NVD
- Recommandations de sécurité
- Détection passive Wi-Fi avec ESP32
- Détection Bluetooth BLE
- Communication USB série
- Historique PostgreSQL
- Interface web
- Docker Desktop

## Technologies

- Python 3.12
- FastAPI
- PostgreSQL 16
- ClamAV
- Docker Compose
- ESP32 DevKit V1
- Arduino IDE

## Installation

1. Installer Docker Desktop.
2. Installer Python 3.12.
3. Installer Git.
4. Créer le fichier .env à partir de .env.example.
5. Lancer Docker Compose.

```powershell
docker compose up -d --build
```

## Interface

http://localhost:8000

## Documentation API

http://localhost:8000/docs

## Bridge ESP32

```powershell
pip install -r bridge/requirements.txt

$env:ESP32_PORT = "COM3"

$env:BRIDGE_TOKEN = "VOTRE_TOKEN"

python bridge/serial_bridge.py
```

## Git

```powershell
git checkout develop
git add .
git commit -m "Nouvelle fonctionnalité"
git push
```
