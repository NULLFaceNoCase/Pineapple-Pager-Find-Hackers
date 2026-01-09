#!/bin/bash
# Title: Find Hackers
# Description: Detects suspicious network and Bluetooth activity that may indicate the presence of nearby hackers.
# Author: NULLFaceNoCase
# Version: 1.0

# ---- FILES ----
LOOT_DIR="/root/loot/find-hackers/"

# ---- BLE ----
BLE_IFACE="hci0"
BT_TIMEOUT="20s"

# ---- WIFI ----
# Min amount an AP needs to change it's SSID to qualify as spoofing
MIN_SPOOFING_COUNT=5
SLEEP_BETWEEN_SCANS=15 # Time to restart wifi and bluetooth searches
aps=()

# ---- REGEX ----
VALID_MAC="([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"
PINEAPPLE_DEFAULT_AP="^pineapple_[0-9A-Fa-f]{4}$"

cleanup() {
    killall hcitool 2>/dev/null
    log_to_file "find-hackers stopped"
    sleep 0.5
    exit
}

setup() {
    mkdir -p "$LOOT_DIR"
    log_to_file "find-hackers starting.. loot = $LOOT_DIR"
}

log_to_file() {
    local msg="$1"
    printf "[$(date +%s)] $msg\n" >> "$LOOT_DIR/collector.log"
}

# Get access points using "_pineap RECON"
get_aps() {
    local search_type="$1"
    local ssid="$2"
    declare -A tmp
    aps=()
    
	pineap_cmd=(_pineap RECON "$search_type")
	
	if [[ -n $ssid ]]; then
	    pineap_cmd+=("$ssid")
	fi

    # Read _pineap output line by line
    while IFS= read -r line; do
        local mac
		mac=$(echo "$line" | grep -Eo "^$VALID_MAC")

        if [ -n "$mac" ]; then
            if [ -z "${tmp[$mac]}" ]; then
                tmp[$mac]="$line"
            else
                tmp[$mac]="${tmp[$mac]}"$'\n'"$line"
            fi
            current_mac="$mac"
        else
            tmp[$current_mac]="${tmp[$current_mac]}"$'\n'"$line"
        fi
    done < <("${pineap_cmd[@]}")

    # Copy tmp to global array
    for mac in "${!tmp[@]}"; do
        aps+=("${tmp[$mac]}")
    done
}

# Alert on suspicous SSIDs
alert_sus_aps() {
	for i in "${!aps[@]}"; do
		mapfile -t SSIDS < <(
		    echo "${aps[$i]}" \
		    | grep -E "B|R" \
		    | sed -E "s/.*'([^']+)'.*/\1/" \
		    | sort -u
		)
		
		MAC=$(echo "${aps[$i]}" | egrep "$VALID_MAC" | awk '{print $1}')
		
		if [ -z "$MAC" ]; then
	        MAC="UNKNOWN"
	    fi
		
		# Check if AP changed SSID and keeps its MAC
	    if (( ${#SSIDS[@]} > 1 )); then
            log_to_file "Found a sus SSID that has changed names SSID List: ${SSIDS[*]} MAC: $MAC"
		    LOG "Found a sus SSID that has changed names\nSSID List: ${SSIDS[*]}\nMAC: $MAC\n"
		    ALERT "Found a sus SSID that has changed names\nSSID List: ${SSIDS[*]}\nMAC: $MAC"
		else
            log_to_file "Found a sus SSID SSID: ${SSIDS[*]} MAC: $MAC"
		    LOG "Found a sus SSID\nSSID: ${SSIDS[*]}\nMAC: $MAC\n"
		    ALERT "Found a sus SSID\nSSID: ${SSIDS[*]}\nMAC: $MAC"
		fi
	done
}

# Log and alert on spoofing SSIDs
log_aps_spoofing_ssids() {
	spoof_count=0
	for i in "${!aps[@]}"; do
		mapfile -t SSIDS < <(
		    echo "${aps[$i]}" \
		    | grep -E "B|R" \
		    | sed -E "s/.*'([^']+)'.*/\1/" \
		    | sort -u
		)
		
		MAC=$(echo "${aps[$i]}" | egrep "$VALID_MAC" | awk '{print $1}')
		
		if [ -z "$MAC" ]; then
	        MAC="UNKNOWN"
	    fi

	    if (( ${#SSIDS[@]} > $MIN_SPOOFING_COUNT )); then
			# Get all SSIDs being spoofed and save to an output file
			dt=$(date +%s)
			output_file="${LOOT_DIR%/}/${dt}_${MAC}_ssid_pool.txt"

		    for ssid in "${SSIDS[@]}"; do
		        echo "$ssid" >> $output_file
		    done

            log_to_file "Found a sus AP spoofing ${#SSIDS[@]} with MAC: $MAC networks SSID Pool saved to $output_file"
		    LOG "Found a sus AP spoofing ${#SSIDS[@]} networks\nMAC: $MAC\nSSID pool saved to $output_file"
		    LOG "Found a sus AP spoofing ${#SSIDS[@]} networks\nMAC: $MAC\nSSID pool saved to $output_file"
		    ((spoof_count++))
		fi
	done
    log_to_file "Found $spoof_count APs spoofing atleast $MIN_SPOOFING_COUNT networks"
	LOG "Found $spoof_count APs spoofing atleast $MIN_SPOOFING_COUNT networks\n"
}

alert_flipper_bt() {
	# Reset Bluetooth adapter to prevent errors/hanging
	hciconfig hci0 down
	hciconfig hci0 up
	
	# Look for Bluetooth devices with flipper in name. Remove duplicates by MAC.
	mapfile -t bt_flippers < <(
		timeout "$BT_TIMEOUT" hcitool -i "$BLE_IFACE" lescan \
		| awk '!seen[$1]++' \
		| grep -i "flipper"
	)

    log_to_file "Found ${#bt_flippers[@]} Bluetooth devices with name 'Flipper'"
	LOG "Found ${#bt_flippers[@]} Bluetooth devices with name 'Flipper'"
	
	# Alert for each BT Flipper device found
	if (( ${#bt_flippers[@]} > 0 )); then
	    for flipper in "${bt_flippers[@]}"; do
			MAC=$(echo "$flipper" | grep -Eo "$VALID_MAC")
			NAME=$(echo "$flipper" | cut -d' ' -f2-)

            log_to_file "Flipper device found BT Name: $NAME BT MAC: $MAC"
			LOG "Flipper device found\nBT Name: $NAME\nBT MAC: $MAC"
			ALERT "Flipper device found\nBT Name: $NAME\nBT MAC: $MAC"
	    done
	fi
}

# Pager default APs
find_pagers() {
    # Management AP default name
    get_aps "ISEARCH" "pager"
    log_to_file "Found ${#aps[@]} APs with SSID 'pager'"
    LOG "Found ${#aps[@]} APs with SSID 'pager'"
    alert_sus_aps

    # Open AP default name
    get_aps "ISEARCH" "pager_open"
    log_to_file "Found ${#aps[@]} APs with SSID 'pager_open'"
    LOG "Found ${#aps[@]} APs with SSID 'pager_open'"
    alert_sus_aps
}

# Wifi Pineapple / Pager with "mimic open networks" & "advertise networks" on
# SSIDs will change rapidly for the same MAC - Karma attack if OPN
find_spoofing_aps() {
    log_to_file "Searching for APs spoofing networks.."
    LOG "Searching for APs spoofing networks..\n"
    get_aps "APS"
    log_aps_spoofing_ssids
}

# Wifi Pineapple default device setup AP
find_pineapples() {
    get_aps "IRSEARCH" "$PINEAPPLE_DEFAULT_AP"
    log_to_file "Found ${#aps[@]} APs with SSID 'Pineapple_XXXX'"
    LOG "Found ${#aps[@]} APs with SSID 'Pineapple_XXXX'\n"
    alert_sus_aps
}

# Flipper default bluetooth name
find_flippers() {
    killall hcitool 2>/dev/null
    log_to_file "Searching for Flipper devices via Bluetooth.."
    LOG "Searching for Flipper devices via Bluetooth.."
    alert_flipper_bt
}

# Trap signals: Ensures cleanup runs on Exit, Ctrl+C (SIGINT) or Kill (SIGTERM)
# SOURCE: oMen (BT Pager Warden payload)
trap cleanup EXIT SIGINT SIGTERM

setup

while true; do
    find_pagers
    find_pineapples
    find_spoofing_aps
    find_flippers
    sleep "$SLEEP_BETWEEN_SCANS"
    LOG "\n"
done