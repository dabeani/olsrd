#!/bin/sh
# Combined OLSRd (IPv4) and OLSRd2 (IPv6) init script for Mikrotik container
# Copyright (C) 2021-2025 FreiesNetz.at & Bernhard Marker


set -eu

# --- Debugging/Logging ---
if [ "${DEBUG:-0}" = "1" ]; then
  set -x
  DEBUGLOG() { echo "[DEBUG] $*" >&2; }
else
  DEBUGLOG() { :; }
fi

echo "Starting Mikrotik OLSRd/OLSRd2 Docker container..."
/bin/busybox uname -a
ip addr show
ip addr
ifconfig
cat /proc/net/dev
echo "Environment variables:"
env

# --- Daemon Control ---
RUN_OLSRD="${RUN_OLSRD:-1}"
RUN_OLSRD2="${RUN_OLSRD2:-1}"

# --- Utility: Find base interface ---
#BASE_IFACE="$(ls /sys/class/net/ | grep -v '^lo$' | head -n 1)"
BASE_IFACE="$(cat /proc/net/dev | grep -v 'Inter-' | grep -v 'packets' | grep -v 'lo' | awk -F: '{print $1}' | tr -d ' ')"
echo "Detected base interface: $BASE_IFACE"

DOCKER_ASSIGNED_IP=$(ip -4 addr show $BASE_IFACE | sed -n 's/.*inet \([^ ]*\).*/\1/p')

# --- VLAN/IP Assignment Helpers (POSIX) ---
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

# --- IPv6 helpers (no 'local' for POSIX) ---
generate_eui64_ipv6() {
  intDev="$1"
  basemac=$(ip link show "$intDev" | awk '/link\/ether/ {print $2}')
  DEBUGLOG "generate_eui64_ipv6: intDev='$intDev', basemac='$basemac'"
  [ -z "$basemac" ] && return
  set -- $(echo "$basemac" | tr ':' ' ')
  b1=$(printf "%02x" $((0x$1 ^ 0x02)))
  result="fe80::${b1}$2:$3ff:fe$4:$5$6/64"
  DEBUGLOG "generate_eui64_ipv6: result='$result'"
  echo "$result"
}

generate_funkfeuer_eui64_ipv6() {
  intDev="$1"
  basemac=$(ip link show "$intDev" | awk '/link\/ether/ {print $2}')
  DEBUGLOG "generate_funkfeuer_eui64_ipv6: intDev='$intDev', basemac='$basemac'"
  [ -z "$basemac" ] && return
  set -- $(echo "$basemac" | tr ':' ' ')
  b1=$(printf "%02x" $((0x$1 ^ 0x02)))
  result="2a02:61:0:ff:${b1}$2:$3ff:fe$4:$5$6/128"
  DEBUGLOG "generate_funkfeuer_eui64_ipv6: result='$result'"
  echo "$result"
}

# --- VLAN and IP assignment (now supports multiple IPv4 per VLAN!) ---
setup_vlans() {
  vlans_str="${vlans:-}"
  parent="${BASE_IFACE:-eth0}"
  max_count="${MAX_VLAN_COUNT:-128}"

  [ -z "$vlans_str" ] && {
    echo "[vlan] No 'vlans' env set; removing ALL VLAN subinterfaces."
    for link in $(ip -o link show | awk -F': ' '{print $2}' | grep "^${parent}\."); do
      remove_vlan "$link"
    done
    return 0
  }

  if command -v mktemp >/dev/null 2>&1; then
    tmp_ids="$(mktemp /tmp/vlan_ids.XXXXXX)" || tmp_ids="/tmp/vlan_ids.$$"
    keep_ids="$(mktemp /tmp/vlan_ids_keep.XXXXXX)" || keep_ids="/tmp/vlan_ids_keep.$$"
  else
    tmp_ids="/tmp/vlan_ids.$$"
    keep_ids="/tmp/vlan_ids_keep.$$"
  fi
  : > "$tmp_ids"

  # Parse each token (space-separated)
  for token in $vlans_str; do
    # Split by comma
    first="$(echo "$token" | cut -d',' -f1)"
    fields="$(echo "$token" | cut -s -d',' -f2-)"
    vlan_ids=""
    # Expand range if needed
    case "$first" in
      *-*)
        start="${first%-*}"
        end="${first#*-}"
        case "$start$end" in *[!0-9]*|'') echo "[vlan] Skipping invalid range: '$first'" >&2; continue ;; esac
        [ "$start" -gt "$end" ] && { tmp="$start"; start="$end"; end="$tmp"; }
        [ "$start" -lt 1 ] && start=1
        [ "$end" -gt 4094 ] && end=4094
        i="$start"
        while [ "$i" -le "$end" ]; do
          vlan_ids="$vlan_ids $i"
          i=$((i+1))
        done
        ;;
      *)
        vlan_ids="$first"
        ;;
    esac

    # Now, process the rest of the fields for IPs
    ip4s=""
    ip6=""
    rest="$fields"
    # POSIX: loop through comma-separated fields
    while [ -n "$rest" ]; do
      this="$(echo "$rest" | cut -d',' -f1)"
      rest="$(echo "$rest" | cut -s -d',' -f2-)"
      if [ -n "$this" ]; then
        if echo "$this" | grep -q ':'; then
          ip6="$this"
        else
          ip4s="$ip4s $this"
        fi
      fi
      [ -z "$rest" ] && break
    done

    # For each VLAN id, output: id|ip4s|ip6
    for id in $vlan_ids; do
      printf '%s|%s|%s\n' "$id" "$ip4s" "$ip6" >> "$tmp_ids"
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
  echo "[vlan] VLANs to keep (count=$total, cap=$max_count): $(awk -F'|' '{print $1}' "$keep_ids" | tr '\n' ' ')"

  # Remove unwanted VLANs
  current_vlans="$(ip -o link show | awk -F': ' '{print $2}' | grep "^${parent}\." | sed -n 's/^.*\.\([0-9]\+\)@.*$/\1/p')"
  for existing_id in $current_vlans; do
    if ! awk -F'|' '{print $1}' "$keep_ids" | grep -qx "$existing_id"; then
      remove_vlan "${parent}.${existing_id}"
    fi
  done

  # Assign IPs: flush only ONCE per iface, assign all IPs
  while IFS='|' read -r id ip4s ip6; do
    [ -n "$id" ] && add_vlan "$parent" "$id" || continue
    iface="${parent}.${id}"
    ip addr flush dev "$iface" 2>/dev/null || true
    ip -6 addr flush dev "$iface" 2>/dev/null || true
    # Assign all IPv4s
    for ip4 in $ip4s; do
      [ -n "$ip4" ] && ip addr add "$ip4" dev "$iface" 2>/dev/null || true
      [ -n "$ip4" ] && echo "[ip] ${iface}: set $ip4"
    done
    # Assign IPv6 (if any)
    if [ -n "$ip6" ]; then
      ip -6 addr add "$ip6" dev "$iface" 2>/dev/null && echo "[ipv6] ${iface}: set $ip6"
    elif [ "$RUN_OLSRD2" = "1" ]; then
      linklocal_ipv6="$(generate_eui64_ipv6 "$iface")"
      ip -6 addr add "$linklocal_ipv6" scope link dev "$iface" 2>/dev/null && echo "[ipv6] ${iface}: set link-local $linklocal_ipv6"
    fi
  done < "$keep_ids"

  rm -f "$tmp_ids" "$keep_ids" "${keep_ids}.lim" 2>/dev/null || true
}

# --- OLSRd IPv4 config ---
generate_olsrd_conf() {
  conf="${OLSRD_CONF:-/etc/olsrd/olsrd.conf}"
  mkdir -p "$(dirname "$conf")"
  : > "$conf"
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
  if [ -n "$OLSRD_LQMULT" ]; then
    for lq in $OLSRD_LQMULT; do
      if echo "$lq" | grep -q ':'; then
        ip="${lq%%:*}"
        mult="${lq#*:}"
      else
        ip="$(echo $lq | awk '{print $1}')"
        mult="$(echo $lq | awk '{print $2}')"
      fi
      if [ -n "$ip" ] && [ -n "$mult" ]; then
        echo "    LinkQualityMult $ip $mult" >> "$conf"
      fi
    done
  fi
  echo "}" >> "$conf"
  echo "" >> "$conf"
  echo "LinkQualityFishEye 1" >> "$conf"
  echo "ClearScreen     yes" >> "$conf"
  echo "" >> "$conf"
  echo "Hna4" >> "$conf"
  echo "{" >> "$conf"
  if [ -n "$OLSRD_HNA4" ]; then
    for entry in $OLSRD_HNA4; do
      ip="$(echo "$entry" | cut -d'/' -f1)"
      mask="$(echo "$entry" | cut -d'/' -f2)"
      iface="$(echo "$entry" | cut -d'/' -f3)"
      [ -z "$iface" ] && iface="$BASE_IFACE"
      if [ -n "$ip" ] && [ -n "$iface" ]; then
        ip route replace "$ip" dev "$iface" 2>/dev/null || ip route add "$ip" dev "$iface" 2>/dev/null
        echo "[hna4] route $ip via $iface"
      fi
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
  iface_list=""
  #for i in $(ls /sys/class/net/ | grep -v '^lo$'); do
  for i in $(cat /proc/net/dev | grep -v 'Inter-' | grep -v 'packets' | grep -v 'lo' | awk -F: '{print $1}' | tr -d ' '); do
    iface_list="$iface_list \"$i\""
  done
  if [ -n "$iface_list" ]; then
    echo "Interface $iface_list { }" >> "$conf"
  fi
  echo "" >> "$conf"
  echo "LoadPlugin \"olsrd_jsoninfo.so.1.1\"" >> "$conf"
  echo "{" >> "$conf"
  echo "  PlParam     \"port\"   \"${OLSRD_JSONINFO_PORT:-9090}\"" >> "$conf"
  echo "  PlParam     \"accept\" \"${OLSRD_JSONINFO_ACCEPT_IP:-127.0.0.1}\"" >> "$conf"
  echo "}" >> "$conf"
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
  echo "" >> "$conf"
  echo "LoadPlugin \"olsrd_watchdog.so.0.1\"" >> "$conf"
  echo "{" >> "$conf"
  echo "  PlParam \"file\" \"/tmp/olsrd.watchdog\"" >> "$conf"
  echo "  PlParam \"interval\" \"5\"" >> "$conf"
  echo "}" >> "$conf"
  echo "" >> "$conf"
  echo "LoadPlugin \"olsrd_txtinfo.so.1.1\"" >> "$conf"
  echo "{" >> "$conf"
  echo "  PlParam \"port\" \"${OLSRD_TXTINFO_PORT:-2006}\"" >> "$conf"
  echo "  PlParam \"accept\" \"${OLSRD_TXTINFO_ACCEPT_IP:-127.0.0.1}\"" >> "$conf"
  echo "}" >> "$conf"

  # olsrd-status-plugin
  if [ -n "${OLSRD_STATUS_PLUGIN:-}" ] && [ "$OLSRD_STATUS_PLUGIN" != "0" ]; then
    echo "" >> "$conf"
    echo "LoadPlugin \"olsrd_status.so.1.0\"" >> "$conf"
    echo "{" >> "$conf"
    if [ -n "${OLSRD_STATUS_PLUGIN_PORT:-}" ]; then
      echo "  PlParam \"Port\" \"$OLSRD_STATUS_PLUGIN_PORT\"" >> "$conf"
    fi
    echo "  PlParam \"Bind\" \"0.0.0.0\"" >> "$conf"
    echo "  PlParam \"assetroot\" \"/usr/share/olsrd-status-plugin/www\"" >> "$conf"
    if [ -n "${OLSRD_STATUS_PLUGIN_NET:-}" ]; then
      for net in $OLSRD_STATUS_PLUGIN_NET; do
        echo "  PlParam \"Net\" \"$net\"" >> "$conf"
      done
    fi
    echo "}" >> "$conf"
  fi
}

# --- OLSRd2 IPv6 config ---
generate_olsrd2_conf() {
  mkdir -p /etc/olsrd2 /var/lock /var/run /var/log /olsrd2/www
  cat <<'EOF' > /etc/olsrd2/olsrd2.conf
[global]
failfast no
fork     no
lockfile /var/lock/olsrd2
pidfile  /var/run/olsrd2.pid

[log]
file   /var/log/olsrd2.log
info   main
info   http
stderr true

[telnet]
port 2009

[http]
bindto 0.0.0.0
bindto ::0
webserver /olsrd2/www
port 8000
acl default_reject
acl first_reject
acl 127.0.0.1
acl 10.0.0.0/8
acl 172.16.0.0/12
acl 192.168.0.0/24
acl 78.41.112.0/21
acl 193.238.156.0/22
acl 185.194.20.0/22
acl ::1
acl 2a02:60::/29

[olsrv2]
originator   -0.0.0.0/0
originator   -::1/128
originator   default_accept
forward_hold_time 50
processing_hold_time 30
tc_interval 5
tc_validity 20

[interface=lo]
bindto       -0.0.0.0/0
bindto       -::1/128
bindto       default_accept
EOF

  vlan_ifaces="$(cat /proc/net/dev | grep -v 'Inter-' | grep -v 'packets' | grep -v 'lo' | awk -F: '{print $1}' | tr -d ' ' | grep -E '^'"$BASE_IFACE"'[.][0-9]+$' || true)"
  if [ -n "$vlan_ifaces" ]; then
    for iface in $vlan_ifaces; do
      cat <<EOL >> /etc/olsrd2/olsrd2.conf
[interface=$iface]
l2default rx_bitrate 10000000
bindto       -0.0.0.0/0
bindto       -::1/128
bindto       default_accept

EOL
    done
  else
    cat <<EOL >> /etc/olsrd2/olsrd2.conf
[interface=$BASE_IFACE]
l2default rx_bitrate 10000000
bindto       -0.0.0.0/0
bindto       -::1/128
bindto       default_accept

EOL
  fi
}

# --- OLSRd (IPv4) Setup ---
if [ "$RUN_OLSRD" = "1" ]; then
  if [ -n "${OLSRD_IP:-}" ]; then
    echo "Remove Docker-assigned IP address from $BASE_IFACE."
    ip addr del $DOCKER_ASSIGNED_IP dev $BASE_IFACE || true
    echo "Add IP $OLSRD_IP from environment variable OLSRD_IP to $BASE_IFACE as main IP."
    ip addr add $OLSRD_IP dev $BASE_IFACE
  fi
fi

# --- VLAN and IP assignment (common, must be before configs) ---
setup_vlans

# --- OLSRd2 (IPv6) Setup ---
if [ "$RUN_OLSRD2" = "1" ]; then
  # Assign Funkfeuer IPv6 to lo
  funkfeuer_ipv6="$(generate_funkfeuer_eui64_ipv6 "$BASE_IFACE")"
  ip -6 addr flush dev lo 2>/dev/null || true
  ip -6 addr add "$funkfeuer_ipv6" dev lo 2>/dev/null && echo "[ipv6] lo: set $funkfeuer_ipv6"
  if ! ip -6 addr show dev lo | grep -q '::1/128'; then
    ip -6 addr add ::1/128 dev lo 2>/dev/null && echo "[ipv6] lo: set ::1/128"
  fi
fi

# --- Generate config files ---
if [ "$RUN_OLSRD" = "1" ]; then
  generate_olsrd_conf
fi
if [ "$RUN_OLSRD2" = "1" ]; then
  generate_olsrd2_conf
fi

# --- Restore Docker-assigned IP after all setup (so container stays reachable) ---
if [ "$RUN_OLSRD" = "1" ] && [ -n "${OLSRD_IP:-}" ]; then
  echo "Add Docker-assigned IP address back to $BASE_IFACE as secondary IP."
  ip addr add $DOCKER_ASSIGNED_IP dev $BASE_IFACE
  echo "Show current configuration of $BASE_IFACE:"
  ip addr show $BASE_IFACE
fi

# --- Socat tunnels (OLSRd only, unchanged) ---
if [ "$RUN_OLSRD" = "1" ]; then
  echo -n "Checking socat environment variable SOCAT_TUNNELS ... "
  if [ -n "${SOCAT_TUNNELS:-}" ]; then
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
fi

# --- Start daemons (both in background if both are chosen, wait so both supervised) ---
olsrd_pid=""
olsrd2_pid=""
if [ "$RUN_OLSRD" = "1" ] && [ "$RUN_OLSRD2" = "1" ]; then
  echo "Starting both OLSRd (IPv4) and OLSRd2 (IPv6) daemons..."
  /usr/sbin/olsrd -nofork &
  olsrd_pid=$!
  /usr/sbin/olsrd2_static -l /etc/olsrd2/olsrd2.conf &
  olsrd2_pid=$!
  # Wait for either process to exit (container stops if either dies)
  wait $olsrd_pid $olsrd2_pid
elif [ "$RUN_OLSRD" = "1" ]; then
  echo "Starting OLSRd daemon (IPv4 only)..."
  exec /usr/sbin/olsrd -nofork
elif [ "$RUN_OLSRD2" = "1" ]; then
  echo "Starting OLSRd2 daemon (IPv6 only)..."
  exec /usr/sbin/olsrd2_static -l /etc/olsrd2/olsrd2.conf
else
  echo "Neither RUN_OLSRD nor RUN_OLSRD2 is set, nothing to do."
  exit 1
fi
