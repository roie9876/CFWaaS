#!/bin/bash
set -euo pipefail

ip -4 address show dev eth0 | grep -q 'inet 172\.22\.10\.4/'
configuration=$(vtysh -c 'show running-config')
grep -q 'network 0.0.0.0/0' <<< "$configuration"
for peer in 172.20.254.4 172.20.254.5 172.25.254.4 172.25.254.5; do
  grep -q "neighbor $peer remote-as 65515" <<< "$configuration"
done
for source in 10.211.0.4/32 10.212.0.4/32; do
  iptables -t nat -C POSTROUTING -s "$source" -j FAAS_NS_EGRESS29
done
pilot_target=$(iptables -t mangle -S FORWARD | awk '$1 == "-A" && $2 == "FORWARD" && $3 == "-s" && $4 == "10.211.0.4/32" && $5 == "-d" && /--set-mss 1200/ {print $6}')
if [[ ! "$pilot_target" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/32$ ]]; then
  printf 'Expected exactly one scoped HTTPS pilot MSS target\n' >&2
  exit 1
fi

install -d -m 0755 /etc/systemd/system/frr.service.d
printf 'FAAS_PILOT_TARGET=%s\n' "$pilot_target" > /etc/faas-ns-persistence.conf
chmod 0600 /etc/faas-ns-persistence.conf
cat > /usr/local/sbin/faas-ns-persistence <<'FAAS_SCRIPT'
#!/bin/bash
set -euo pipefail
. /etc/faas-ns-persistence.conf
if ! iptables -t nat -nL FAAS_NS_EGRESS29 >/dev/null 2>&1; then
  iptables -t nat -N FAAS_NS_EGRESS29
  for excluded in 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.0.0.0/24 192.168.0.0/16 198.18.0.0/15 224.0.0.0/4 240.0.0.0/4; do
    iptables -t nat -A FAAS_NS_EGRESS29 -d "$excluded" -j RETURN
  done
  iptables -t nat -A FAAS_NS_EGRESS29 -o eth0 -j MASQUERADE
fi
for source in 10.211.0.4/32 10.212.0.4/32; do
  iptables -t nat -C POSTROUTING -s "$source" -j FAAS_NS_EGRESS29 2>/dev/null || iptables -t nat -A POSTROUTING -s "$source" -j FAAS_NS_EGRESS29
done
iptables -t mangle -C FORWARD -s 10.211.0.4/32 -d "$FAAS_PILOT_TARGET" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1200 2>/dev/null || iptables -t mangle -A FORWARD -s 10.211.0.4/32 -d "$FAAS_PILOT_TARGET" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1200
iptables -t mangle -C FORWARD -s "$FAAS_PILOT_TARGET" -d 10.211.0.4/32 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1200 2>/dev/null || iptables -t mangle -A FORWARD -s "$FAAS_PILOT_TARGET" -d 10.211.0.4/32 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1200
FAAS_SCRIPT
chmod 0755 /usr/local/sbin/faas-ns-persistence
cat > /etc/systemd/system/faas-ns-persistence.service <<'FAAS_SERVICE'
[Unit]
After=network-pre.target systemd-sysctl.service
Wants=network-pre.target
Before=frr.service
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/faas-ns-persistence
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
FAAS_SERVICE
cat > /etc/systemd/system/frr.service.d/faas-ns-persistence.conf <<'FAAS_FRR'
[Unit]
After=faas-ns-persistence.service
Requires=faas-ns-persistence.service
FAAS_FRR
cp -n /etc/frr/frr.conf /etc/frr/frr.conf.faas-before-ns-persistence
vtysh -c 'write memory'
systemctl daemon-reload
systemctl enable faas-ns-persistence.service frr.service
systemctl start faas-ns-persistence.service
systemctl is-active --quiet faas-ns-persistence.service
systemctl is-active --quiet frr.service