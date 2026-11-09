
#include <WiFi.h>
#include <BLEDevice.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>
#include <ArduinoJson.h>

BLEScan* bleScanner;

unsigned long lastScan = 0;

void sendDevice(
    const char* type,
    const String& name,
    const String& address,
    int rssi,
    int channel = 0
) {
    StaticJsonDocument<256> doc;
    
    doc["type"] = type;
    doc["name"] = name;
    doc["address"] = address;
    doc["rssi"] = rssi;

    if (channel > 0) {
        doc["channel"] = channel;
    }

    serializeJson(doc, Serial);
    Serial.println();
}

// --------------------------------------
// WIFI PASSIVE DISCOVERY
// --------------------------------------

void scanWiFi() {

    int count = WiFi.scanNetworks(false, true);

    if (count < 0) {
        Serial.println("{\"type\":\"status\",\"name\":\"WiFi scan error\"}");
        return;
    }

    for (int i = 0; i < count; i++) {

        String name = WiFi.SSID(i);
        String address = WiFi.BSSIDstr(i);

        int rssi = WiFi.RSSI(i);
        int channel = WiFi.channel(i);

        sendDevice(
            "wifi",
            name,
            address,
            rssi,
            channel
        );

        delay(20);
    }

    WiFi.scanDelete();
}

// --------------------------------------
// BLUETOOTH BLE DISCOVERY
// --------------------------------------


void scanBluetooth() {

    BLEScanResults results = bleScanner->start(5, false);

    int count = results.getCount();

    for (int i = 0; i < count; i++) {

        BLEAdvertisedDevice device =
            results.getDevice(i);

        String name = "Inconnu";

        if (device.haveName()) {
            name = String(device.getName().c_str());
        }

        String address =
            String(device.getAddress().toString().c_str());

        int rssi = device.getRSSI();

        sendDevice(
            "bluetooth",
            name,
            address,
            rssi
        );
    }

    bleScanner->clearResults();
}


    bleScanner->clearResults();
}

// --------------------------------------
// SETUP
// --------------------------------------

void setup() {

    Serial.begin(115200);

    WiFi.mode(WIFI_STA);
    WiFi.disconnect();

    BLEDevice::init("CyberShield-ESP32");

    bleScanner = BLEDevice::getScan();

    bleScanner->setActiveScan(false);
    bleScanner->setInterval(100);
    bleScanner->setWindow(99);

    Serial.println(
        "{\"type\":\"status\",\"name\":\"ESP32_READY\"}"
    );
}

// --------------------------------------
// LOOP
// --------------------------------------

void loop() {

    if (millis() - lastScan >= 30000) {

        lastScan = millis();

        scanWiFi();
        scanBluetooth();
    }

    delay(100);
}
