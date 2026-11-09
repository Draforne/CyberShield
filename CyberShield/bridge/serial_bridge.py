
import os
import json
import time
import serial
import requests

PORT = os.getenv("ESP32_PORT", "COM3")
BAUDRATE = 115200

API_URL = os.getenv(
    "API_URL",
    "http://localhost:8000/api/devices/ingest"
)

TOKEN = os.getenv("BRIDGE_TOKEN")

if not TOKEN:
    raise RuntimeError("BRIDGE_TOKEN doit être configuré.")

headers = {
    "X-Bridge-Token": TOKEN
}


def main():

    print("CyberShield USB Bridge")
    print("Port :", PORT)

    while True:

        try:
            with serial.Serial(
                PORT,
                BAUDRATE,
                timeout=2
            ) as esp32:

                print("ESP32 connecté !")

                while True:

                    line = esp32.readline().decode(
                        "utf-8",
                        errors="replace"
                    ).strip()

                    if not line:
                        continue

                    try:
                        data = json.loads(line)

                    except json.JSONDecodeError:
                        print("Message ignoré :", line)
                        continue

                    if data.get("type") not in (
                        "wifi", "bluetooth"
                    ):
                        continue

                    try:
                        response = requests.post(
                            API_URL,
                            json=data,
                            headers=headers,
                            timeout=5
                        )

                        response.raise_for_status()

                        print(
                            "Enregistré :",
                            data.get("type"),
                            data.get("name")
                        )

                    except requests.RequestException as exc:
                        print("Erreur API :", exc)

        except (serial.SerialException, OSError) as exc:

            print("Connexion USB indisponible :", exc)
            print("Nouvelle tentative dans 5 secondes...")
            time.sleep(5)


if __name__ == "__main__":
    main()
