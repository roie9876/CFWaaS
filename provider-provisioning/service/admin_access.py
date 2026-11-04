"""Bounded public IPv4 admin sources; never customer workload routing prefixes."""
import ipaddress
import re


MAX_ADMIN_SOURCES = 16
_NON_PUBLIC = tuple(ipaddress.IPv4Network(prefix) for prefix in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
    "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
))


def normalize_admin_sources(value: object) -> list[str]:
    if not isinstance(value, list) or len(value) > MAX_ADMIN_SOURCES:
        raise ValueError("Admin sources must be a list of at most 16 public IPv4 hosts or CIDRs")
    result = set()
    for item in value:
        if not isinstance(item, str) or not re.fullmatch(r"[0-9.]+(?:/[0-9]{1,2})?", item.strip()):
            raise ValueError("Invalid public IPv4 admin source")
        try:
            network = ipaddress.IPv4Network(item.strip(), strict=True)
        except ValueError:
            raise ValueError("Invalid public IPv4 admin source") from None
        if (network.prefixlen == 0 or not network.is_global
                or any(network.overlaps(prefix) for prefix in _NON_PUBLIC)):
            raise ValueError("Admin sources must contain only public unicast IPv4 addresses")
        result.add(str(network))
    return sorted(result)
