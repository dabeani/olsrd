#!/bin/sh
# Copyright (C) 2021 FreiesNetz.at & Bernhard Marker 2025
echo "Starting OLSRd Docker container for Mikrotik RouterOS..."
/bin/busybox uname -a

echo "--- redirect to tmp logfile!"

echo "Environment variables:"
env

# Detect base interface (first non-loopback)
BASE_IFACE="$(ls /sys/class/net/ | grep -v '^lo$' | head -n 1)"
echo "Detected base interface: $BASE_IFACE"

if [ -n "$OLSRD_VERBOSE" ]; then
  exec > /tmp/olsrd-init-full.log 2>&1
fi

DOCKER_ASSIGNED_IP=$(ip -4 addr show eth0 | sed -n 's/.*inet \([^ ]*\).*/\1/p')


# --- VLAN setup + OLSRD_IP assignment (POSIX/ash) -----------------------------
# (VLAN setup code remains unchanged, but config file generation is now dynamic)

add_vlan() {
  parent="$1"
  id="$2"
  sub="${parent}.${id}"

  if [ "$id" -lt 1 ] || [ "$id" -gt 4094 ]; then
    echo "[vlan] Skipping out-of-range VLAN ID: $id" >&2
    return 0
  fi

  if ip link show "$sub" >/dev/null 2>&1; then
    echo "[vlan] $sub already exists, skipping creation."
    return 0
  fi

  echo "[debug] add_vlan: parent=$parent id=$id sub=$sub"
  if ip link add link "$parent" name "$sub" type vlan id "$id" 2>&1; then
    echo "[debug] ip link add succeeded for $sub"
  elif command -v vconfig >/dev/null 2>&1; then
    echo "[debug] vconfig add $parent $id"
    vconfig add "$parent" "$id" 2>&1
    echo "[debug] vconfig exit code: $?"
  else
    echo "[vlan] Failed to create $sub (need 'ip link add ... type vlan' or 'vconfig')." >&2
    echo "[debug] Failed to create $sub (no ip link add or vconfig)"
    return 1
  fi

  ip link set dev "$sub" up 2>/dev/null || true
  echo "[vlan] Created and up: $sub"
}

remove_vlan() {
  sub="$1"
  if ip link show "$sub" >/dev/null 2>&1; then
    ip link set dev "$sub" down 2>/dev/null || true
    ip link delete "$sub" 2>/dev/null || true
    echo "[vlan] Removed: $sub"
  fi
}

setup_vlans() {
  vlans_str="${vlans:-}"
  echo "VLANs to set up: $vlans_str"

  if [ -n "${INTERFACES:-}" ]; then
    set -- $INTERFACES
    parent="$1"
    shift
    extra_ifaces="$*"
  else
    parent=""
    for iface in $(ip -o link show | awk -F': ' '{print $2}' | grep -E '^eth[0-9]+$'); do
      parent="$iface"
      break
    done
    extra_ifaces=""
  fi

  if [ -z "$vlans_str" ]; then
    echo "[vlan] No 'vlans' env set; removing ALL VLAN subinterfaces."
    if [ -n "$parent" ]; then
      for link in $(ip -o link show | awk -F': ' '{print $2}' | grep "^${parent}\."); do
        remove_vlan "$link"
      done
    fi
    return 0
  fi

  if [ -z "$parent" ]; then
    echo "[vlan] Could not determine parent interface (no INTERFACES and no ethX found). Aborting VLAN setup." >&2
    return 1
  fi

  max_count="${MAX_VLAN_COUNT:-4094}"

  if command -v mktemp >/dev/null 2>&1; then
    tmp_ids="$(mktemp /tmp/vlan_ids.XXXXXX)" || tmp_ids="/tmp/vlan_ids.$$"
    keep_ids="$(mktemp /tmp/vlan_ids_keep.XXXXXX)" || keep_ids="/tmp/vlan_ids_keep.$$"
  else
    tmp_ids="/tmp/vlan_ids.$$"
    keep_ids="/tmp/vlan_ids_keep.$$"
  fi
  : > "$tmp_ids"

  last_ips=""
  for token in $vlans_str; do
    case "$token" in
      *,*)
        vlan_part="$(echo "$token" | cut -d',' -f1)"
        ip_part="$(echo "$token" | cut -d',' -f2-)"
        last_ips="$ip_part"
        ;;
      *)
        vlan_part="$token"
        last_ips=""   # <-- Reset last_ips if no explicit IP given!
        ;;
    esac
    # Expand VLAN ranges and single VLANs
    for vlan_item in $(echo "$vlan_part" | tr ',' ' '); do
      case "$vlan_item" in
        *-*)
          start="${vlan_item%-*}"
          end="${vlan_item#*-}"
          case "$start$end" in
            *[!0-9]*|'' ) echo "[vlan] Skipping invalid range: '$vlan_item'" >&2; continue ;;
          esac
          if [ "$start" -gt "$end" ]; then tmp="$start"; start="$end"; end="$tmp"; fi
          [ "$start" -lt 1 ] && start=1
          [ "$end" -gt 4094 ] && end=4094
          i="$start"
          while [ "$i" -le "$end" ]; do
            printf '%s %s\n' "$i" "$last_ips" >> "$tmp_ids"
            i=$((i+1))
          done
          ;;
        *)
          id="$vlan_item"
          case "$id" in
            *[!0-9]*|'' ) echo "[vlan] Skipping invalid VLAN ID: $id" >&2; continue ;;
          esac
          if [ "$id" -ge 1 ] && [ "$id" -le 4094 ]; then
            printf '%s %s\n' "$id" "$last_ips" >> "$tmp_ids"
          else
            echo "[vlan] Skipping out-of-range VLAN ID: $id" >&2
          fi
          ;;
      esac
    done
  done

  sort -n -u "$tmp_ids" > "$keep_ids"
  total="$(wc -l < "$keep_ids" | awk '{print $1}')"
  if [ "$total" -gt "$max_count" ]; then
    echo "[vlan] Requested $total VLANs; limiting to first $max_count per MAX_VLAN_COUNT." >&2
    head -n "$max_count" "$keep_ids" > "${keep_ids}.lim" && mv "${keep_ids}.lim" "$keep_ids"
    total="$max_count"
  fi

  echo "[vlan] Parent interface: $parent"
  echo "[vlan] VLANs to keep (count=$total, cap=$max_count): $(awk '{print $1}' "$keep_ids" | tr '\n' ' ')"

  # Correct extraction of VLAN IDs from interface names
  current_vlans="$(ip -o link show | awk -F': ' '{print $2}' | grep "^${parent}\." | sed -n 's/^.*\.\([0-9]\+\)@.*$/\1/p')"
  echo "[vlan] Existing VLANs on $parent: $current_vlans"
  echo "[vlan] VLANs to keep: $(awk '{print $1}' "$keep_ids" | tr '\n' ' ')"
  for existing_id in $current_vlans; do
    if ! awk '{print $1}' "$keep_ids" | grep -qx "$existing_id"; then
      echo "[vlan] Removing ${parent}.${existing_id} (not in keep list)"
      remove_vlan "${parent}.${existing_id}"
    else
      echo "[vlan] Keeping ${parent}.${existing_id}"
    fi
  done

  # Assign all IPs (comma separated, with CIDR) to the interface, flush only once per interface
  while IFS=' ' read -r id ips; do
    [ -n "$id" ] && add_vlan "$parent" "$id" || true
    iface="${parent}.${id}"
    ip addr flush dev "$iface" 2>/dev/null || true
    if [ -n "$ips" ]; then
      ips_clean="$(echo "$ips" | tr -d ' ')"
      for ipaddr in $(echo "$ips_clean" | tr ',' ' '); do
        if echo "$ipaddr" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$'; then
          ip addr add "$ipaddr" dev "$iface" 2>/dev/null || true
          echo "[ip] ${iface}: set $ipaddr"
        else
          echo "[ip] ${iface}: invalid IP/CIDR '$ipaddr', skipping." >&2
        fi
      done
    elif [ -n "${OLSRD_IP:-}" ]; then
      ip addr add "$OLSRD_IP" dev "$iface" 2>/dev/null || true
      echo "[ip] ${iface}: set $OLSRD_IP"
    fi
  done < "$keep_ids"

  if [ -n "${OLSRD_IP:-}" ]; then
    for IFACE in "$parent" $extra_ifaces; do
      if ip link show "$IFACE" >/dev/null 2>&1; then
        ip addr flush dev "$IFACE" 2>/dev/null || true
        ip addr add "$OLSRD_IP" dev "$IFACE" 2>/dev/null || true
        echo "[ip] ${IFACE}: set $OLSRD_IP"
      else
        echo "[ip] ${IFACE}: interface not found, skipping." >&2
      fi
    done
  else
    echo "[ip] OLSRD_IP not set; skipping IP assignment."
  fi

  rm -f "$tmp_ids" "$keep_ids" "${keep_ids}.lim" 2>/dev/null || true
}

# --- OLSRd config generation ---
generate_olsrd_conf() {
  conf="${OLSRD_CONF:-/etc/olsrd/olsrd.conf}"
  mkdir -p "$(dirname "$conf")"
  : > "$conf"

  # MainIp from OLSRD_IP (strip CIDR if present)
  mainip="${OLSRD_IP%%/*}"
  echo "DebugLevel      0" >> "$conf"
  echo "IpVersion       4" >> "$conf"
  echo "MainIp $mainip" >> "$conf"

  echo "" >> "$conf"
  echo "InterfaceDefaults" >> "$conf"
  echo "{" >> "$conf"
  echo "  Ip4Broadcast 255.255.255.255" >> "$conf"
  echo "    HelloInterval       1.0" >> "$conf"
  echo "    HelloValidityTime       300.0" >> "$conf"
  echo "    TcInterval          3.0" >> "$conf"
  echo "    TcValidityTime      300.0" >> "$conf"
  echo "    MidInterval         30.0" >> "$conf"
  echo "    MidValidityTime     500.0" >> "$conf"
  echo "    HnaInterval         30.0" >> "$conf"
  echo "    HnaValidityTime     500.0" >> "$conf"
  # LinkQualityMult entries (support IP:mult and IP mult, multiple entries)
  if [ -n "$OLSRD_LQMULT" ]; then
    for lq in $OLSRD_LQMULT; do
      # If entry contains ':', split on ':'
      if echo "$lq" | grep -q ':'; then
        ip="${lq%%:*}"
        mult="${lq#*:}"
      else
        # Otherwise, split on space
        ip="$(echo $lq | awk '{print $1}')"
        mult="$(echo $lq | awk '{print $2}')"
      fi
      # Only write if both ip and mult are present
      if [ -n "$ip" ] && [ -n "$mult" ]; then
        echo "    LinkQualityMult $ip $mult" >> "$conf"
      fi
    done
  fi
  echo "}" >> "$conf"

  echo "" >> "$conf"
  echo "LinkQualityFishEye 1" >> "$conf"
  echo "ClearScreen     yes" >> "$conf"

  # Hna4 block and routing
  echo "" >> "$conf"
  echo "Hna4" >> "$conf"
  echo "{" >> "$conf"
  if [ -n "$OLSRD_HNA4" ]; then
    for entry in $OLSRD_HNA4; do
      ip="$(echo "$entry" | cut -d'/' -f1)"
      mask="$(echo "$entry" | cut -d'/' -f2)"
      iface="$(echo "$entry" | cut -d'/' -f3)"
      # If iface is empty, use BASE_IFACE
      [ -z "$iface" ] && iface="$BASE_IFACE"
      # Add route for each entry
      if [ -n "$ip" ] && [ -n "$iface" ]; then
        ip route replace "$ip" dev "$iface" 2>/dev/null || ip route add "$ip" dev "$iface" 2>/dev/null
        echo "[hna4] route $ip via $iface"
      fi
      # Write only IP and netmask to config
      if [ -n "$ip" ] && [ -n "$mask" ]; then
        echo "$ip $mask" >> "$conf"
      fi
    done
  fi
  echo "}" >> "$conf"

  echo "" >> "$conf"
  echo "Hna6" >> "$conf"
  echo "{" >> "$conf"
  echo "}" >> "$conf"

  echo "" >> "$conf"
  echo "AllowNoInt  yes" >> "$conf"
  echo "Willingness     3" >> "$conf"

  echo "" >> "$conf"
  echo "IpcConnect" >> "$conf"
  echo "{" >> "$conf"
  echo "     MaxConnections  0" >> "$conf"
  echo "     Host            127.0.0.1" >> "$conf"
  echo "}" >> "$conf"

  echo "" >> "$conf"
  echo "UseHysteresis   no" >> "$conf"
  echo "LinkQualityLevel    2" >> "$conf"
  echo "Pollrate    0.1" >> "$conf"
  echo "TcRedundancy    2" >> "$conf"
  echo "MprCoverage 5" >> "$conf"

  echo "" >> "$conf"
  # Interface block: collect all interfaces from /sys/class/net (except lo)
  iface_list=""
  for i in $(ls /sys/class/net/ | grep -v '^lo$'); do
    iface_list="$iface_list \"$i\""
  done
  if [ -n "$iface_list" ]; then
    echo "Interface $iface_list { }" >> "$conf"
  fi

  # Plugins
  # JSONinfo
  echo "" >> "$conf"
  echo "LoadPlugin \"olsrd_jsoninfo.so.1.1\"" >> "$conf"
  echo "{" >> "$conf"
  echo "  PlParam     \"port\"   \"${OLSRD_JSONINFO_PORT:-9090}\"" >> "$conf"
  echo "  PlParam     \"accept\" \"${OLSRD_JSONINFO_ACCEPT_IP:-127.0.0.1}\"" >> "$conf"
  echo "}" >> "$conf"

  # HTTPinfo
  echo "" >> "$conf"
  echo "LoadPlugin \"olsrd_httpinfo.so.0.1\"" >> "$conf"
  echo "{" >> "$conf"
  echo "  PlParam \"Port\" \"${OLSRD_HTTPINFO_PORT:-8080}\"" >> "$conf"
  if [ -n "$OLSRD_HTTPINFO_ALLOW_NET" ]; then
    for net in $OLSRD_HTTPINFO_ALLOW_NET; do
      ip="$(echo $net | cut -d'/' -f1)"
      mask="$(echo $net | cut -d'/' -f2)"
      echo "  PlParam \"Net\" \"$ip $mask\"" >> "$conf"
    done
  else
    echo "  PlParam \"Net\"   \"0.0.0.0 0.0.0.0\"" >> "$conf"
  fi
  echo "}" >> "$conf"

  # Watchdog
  echo "" >> "$conf"
  echo "LoadPlugin \"olsrd_watchdog.so.0.1\"" >> "$conf"
  echo "{" >> "$conf"
  echo "  PlParam \"file\" \"/tmp/olsrd.watchdog\"" >> "$conf"
  echo "  PlParam \"interval\" \"5\"" >> "$conf"
  echo "}" >> "$conf"

  # TXTinfo
  echo "" >> "$conf"
  echo "LoadPlugin \"olsrd_txtinfo.so.1.1\"" >> "$conf"
  echo "{" >> "$conf"
  echo "  PlParam \"port\" \"${OLSRD_TXTINFO_PORT:-2006}\"" >> "$conf"
  echo "  PlParam \"accept\" \"${OLSRD_TXTINFO_ACCEPT_IP:-127.0.0.1}\"" >> "$conf"
  echo "}" >> "$conf"

    # olsrd-status-plugin
if [ -n "$OLSRD_STATUS_PLUGIN" ]; then
  echo "" >> "$conf"
  echo "LoadPlugin \"olsrd_status.so.1.0\"" >> "$conf"
  echo "{" >> "$conf"
#  echo "  PlParam \"Port\" \"11080\"" >> "$conf"
  echo "  PlParam \"Bind\" \"0.0.0.0\"" >> "$conf"
#  echo "  PlParam \"EnableIPv6\" \"no\"" >> "$conf"
  echo "  PlParam \"assetroot\" \"/usr/share/olsrd-status-plugin/www\"" >> "$conf"
  echo "}" >> "$conf"
fi
}


# Docker automatically assigns an IP address on eth0 but OLSRd requires the
# user-wanted IP address to be used as first primary main IP address.
# So remove the Docker assigned IP and set the user-wanted IP/mask.
# But because Docker will not start the container without its IP, we have to
# add it back again later on after setting the user-wanted IP/mask.
echo "Remove Docker-assigned IP address from eth0."
ip addr del $DOCKER_ASSIGNED_IP dev eth0
echo "Add IP $OLSRD_IP from environment variable OLSRD_IP to eth0 as main IP."
ip addr add $OLSRD_IP dev eth0

# Run VLAN + IP setup
setup_vlans

# Generate the full OLSRd config file
generate_olsrd_conf

echo "Add Docker-assigned IP address back to eth0 as secondary IP."
ip addr add $DOCKER_ASSIGNED_IP dev eth0
echo "Show current configuration of eth0:"
ip addr show eth0

# Socat tunnels (unchanged)
echo -n "Checking socat environment variable SOCAT_TUNNELS ... "
if [ -n "$SOCAT_TUNNELS" ]; then
  echo $SOCAT_TUNNELS
  for tunnel in $SOCAT_TUNNELS; do
    listenport=$(echo $tunnel | /bin/busybox cut -d: -f1)
    destination=$(echo $tunnel | /bin/busybox cut -d: -f2)
    dstport=$(echo $tunnel | /bin/busybox cut -d: -f3)
    echo -n "Running tunnel from listen-port $listenport to destination $destination:$dstport ... "
    /usr/bin/socat TCP-LISTEN:$listenport,fork TCP:$destination:$dstport &
    echo "done."
  done
else
  echo 'none set (example: "22:172.17.0.1:22 80:172.17.0.1:80 8291:172.17.0.1:8291" ).'
fi

echo "Running OLSR daemon ..."
/usr/sbin/olsrd -nofork
