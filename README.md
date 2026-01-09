# :feelsgood: Find Hackers 
WiFi + BLE passive hacker detection payload for Hak5 Pineapple Pager. 

Designed for the **Hak5 Pineapple Pager**, capable of detecting suspicious network and Bluetooth activity and identifying nearby devices that may resemble and operate like common hacking tools (Pineapple Pager, WiFi Pineapple, and Flipper device).

> ⚠️ **For authorized security research, red-teaming, and situational awareness only.**  
> You are responsible for complying with all laws in your region.

---

## ✨ Features

| Feature | Description |
|--------|-------------|
| **WiFi Detection** | Uses `_pineap RECON` to search for APs using SSIDs commonly found with Hak5 devices  |
| **BLE Detection** | Uses `lescan` for BT filtering |
| **Continuous Monitor Mode** | Cycles WiFi → BLE → sleep delay — loops forever |
| **Logging** | Each hit is archived with timestamps |
| **SSID Pool Loot** | Logs SSID pool of spoofing APs |

---

## 📁 Output Storage Structure


Log location:
*Timestamps are in Epoch*
```
/root/loot/find-hackers/collector.log
```

If an AP is found to be spoofing SSID names like a Karma attack, a file will be created of all of the SSID names. This can contain SSIDs pulled in from a Pineapple Pager's SSID pool and could potentially be used to track a hacker's movements using
[Wigle](https://wigle.net/).


Output location:
```
/root/loot/find-hackers/<EPOCH_DATETIME>_<MAC>_ssid_pool.txt
```

---

## 🔧 Configuration

```bash
# ---- FILES ----
LOOT_DIR="/root/loot/find-hackers/"

# ---- BLE ----
BLE_IFACE="hci0"
BT_TIMEOUT="20s"

# ---- WIFI ----
# Min amount an AP needs to change it's SSID to qualify as spoofing
MIN_SPOOFING_COUNT=5
SLEEP_BETWEEN_SCANS=15 # Time to restart wifi and bluetooth searches
```

---
## TODO
- Search for duplicate WPA networks with unrelated MACs - potential evil twin
- Add channel and strength for wifi hits
- Add GPS coordinates in logs when hits are found
- Look at PCAPs search for Alfa card activity
- Ubertooth One
- Pwnagotchi