# Find Hackers 
WiFi + BLE passive hacker detection payload for Hak5 Pineapple Pager. 

Designed for the **Hak5 Pineapple Pager**, capable of detecting suspicious network and Bluetooth activity and identifying nearby devices that may resemble and operate like common hacking tools (Pineapple Pager, WiFi Pineapple, and Flipper device).

> **For authorized security research, red-teaming, and situational awareness only.**  
> You are responsible for complying with all laws in your region.

---

## Features

| Feature | Description |
|--------|-------------|
| **WiFi SSID Detection** | Uses `_pineap RECON` to search for APs using SSIDs commonly found with Hak5 devices and stingray hunter hotspot  |
| **WiFi Attacks Detection** | Searches for APs rapidly changing their SSID and potential evil twins  |
| **BLE Detection** | Uses `lescan` for BT filtering |
| **Continuous Monitor Mode** | Cycles WiFi → BLE → sleep delay — loops forever |
| **Logging** | Each hit is archived with timestamps |
| **SSID Pool Loot** | Logs SSID pool of spoofing APs |

---

## Output Storage Structure


Log location:
*Timestamps are in Epoch*
```
/root/loot/find-hackers/collector.log
```

JSON file containing APs from recon
```
/root/loot/find-hackers/all_aps.json
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
RECON_OUTPUT_JSON="/root/loot/find-hackers/all_aps.json"

# ---- BLE ----
BLE_IFACE="hci0"
BLE_SCAN_SECONDS=30
BT_TIMEOUT="20s"

# ---- WIFI ----
# Min amount an AP needs to change it's SSID to qualify as spoofing
MIN_SPOOFING_COUNT=5
SLEEP_BETWEEN_SCANS=15 # Time to restart wifi and bluetooth searches
```

---
## TODO
- Only look at WPA2/3 networks for evil twin. _pineap RECON doesnt currently support encryption
- Add GPS coordinates in logs when hits are found
- Search for SSIDs on restriced channels