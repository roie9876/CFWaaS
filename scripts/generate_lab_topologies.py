#!/usr/bin/env python3
"""Generate the active EW-18 topology and the historical archived EW-21 prototype."""
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VM = "img/lib/azure2/compute/Virtual_Machine.svg"
NIC = "img/lib/azure2/networking/Network_Interfaces.svg"
BLUE = "#0078d4"
ORANGE = "#ff8c00"
PURPLE = "#5c2d91"
TEAL = "#00897b"
INK = "#243746"


def save(path, document):
    ET.indent(document, space="  ")
    path.write_bytes(ET.tostring(document, encoding="utf-8", xml_declaration=True))


def update_style(cell, **updates):
    parts = cell.get("style", "").split(";")
    flags = [p for p in parts if p and "=" not in p]
    values = dict(p.split("=", 1) for p in parts if "=" in p)
    values.update({k: str(v) for k, v in updates.items()})
    cell.set("style", ";".join([*flags, *(k + "=" + v for k, v in values.items())]) + ";")


def restyle_ew18():
    document = ET.Element("mxfile", host="app.diagrams.net", version="24.0.0", type="device")
    diagram = ET.SubElement(document, "diagram", id="ew18-managed-vpn-inspection", name="EW-18 through EW-24")
    model = ET.SubElement(diagram, "mxGraphModel", dx="2300", dy="1730", grid="1", gridSize="10",
                          guides="1", tooltips="1", connect="1", arrows="1", fold="1", page="1",
                          pageScale="1", pageWidth="2300", pageHeight="1730", math="0", shadow="0")
    root = ET.SubElement(model, "root")
    ET.SubElement(root, "mxCell", id="0")
    ET.SubElement(root, "mxCell", id="1", parent="0")
    vertex(root, "title", "EW-18 → EW-24 | Managed IPsec + two Ubuntu NVAs + internal HA-ports LB",
           30, 20, 2240, 60, size=28, stroke="#ffffff")
    vertex(root, "flow-summary",
           "ONE physical lab tenant / subscription; customer and provider are logical roles.\n"
           "Source > managed RA > CI > IPsec > PI > LB VIP > NVA1 OR NVA2 > PD > IPsec > CD > destination.",
           30, 90, 2240, 70, size=21, fill="#fff9cc", stroke="#d6b656")
    for side, x, colour, fill in (("provider", 30, BLUE, "#e6f2ff"), ("customer", 1170, ORANGE, "#fff4e6")):
        vertex(root, side, "FWaaS " + side.upper() + " | logical lab role",
               x, 180, 1100, 1300, fill=fill, stroke=colour, size=24, border=3)

    def network(identifier, label, x, y, width, height, side):
        return vertex(root, identifier, label, x, y, width, height, side,
                      fill="#d9eaff" if side == "provider" else "#ffead1", size=21, border=4)

    def subnet(identifier, label, x, y, width, height, parent):
        return vertex(root, identifier, label, x, y, width, height, parent,
                      fill="#ffffff", dashed=True)

    def icon(identifier, label, x, y, parent, image=VM, label_width=300):
        cell = vertex(root, identifier, label, x, y, 80, 80, parent, image=True)
        update_style(cell, image=image, labelWidth=label_width)
        return cell

    gateway = "img/lib/azure2/networking/Virtual_Network_Gateways.svg"
    for role, side, x, y, cidr, label in (
        ("pi", "provider", 620, 70, "172.26", "Provider ingress GW\nIPsec decrypt"),
        ("pd", "provider", 620, 950, "172.31", "Provider delivery GW\nIPsec encrypt / ASN 65031"),
        ("ci", "customer", 30, 70, "172.28", "Customer ingress GW"),
        ("cd", "customer", 30, 950, "172.29", "Customer delivery GW\nASN 65021"),
    ):
        ingress = role.endswith("i")
        name = side + ("-ingress" if ingress else "-delivery")
        network(name, ("Ingress" if ingress else "Delivery") + " hub VNet\n" + cidr + ".0.0/16",
                x, y, 630 if side == "customer" and ingress else 440, 280, side)
        subnet(role + "-subnet", "GatewaySubnet", 20, 75, 300, 175, name)
        icon(role, label, 140, 35, role + "-subnet", gateway)
    subnet("ra-subnet", "Appliance subnet", 340, 75, 270, 175, "customer-ingress")
    icon("ra", "Routing Appliance\nONE managed resource", 95, 35, "ra-subnet",
         "img/lib/azure2/networking/Virtual_Router.svg", 250)

    for letter, y, prefix in (("a", 90, "10.151"), ("b", 970, "10.152")):
        network("vnet-" + letter, "Workload VNet-" + letter.upper() + "\n" + prefix + ".0.0/16",
                780, y, 280, 280, "customer")
        subnet("subnet-" + letter, "Workload subnet /24", 20, 75, 240, 175, "vnet-" + letter)
        icon("vm-" + letter, "VM-" + letter.upper() + "\n" + prefix + ".0.4",
             80, 35, "subnet-" + letter, label_width=220)

    network("security-vnet", "Provider security VNet | 172.30.0.0/16 | no local gateway",
            40, 380, 1020, 460, "provider")
    subnet("fw-subnet", "Firewall subnet | 172.30.10.0/24 | same subnet for both backends",
           20, 75, 980, 345, "security-vnet")
    icon("lb", "Internal Standard LB\nVIP 172.30.10.10", 70, 100, "fw-subnet",
         "img/lib/azure2/networking/Load_Balancers.svg", 240)
    icon("fw", "NVA1 | vm-cvpn-ew18-fw\n172.30.10.4 / eth0\nNO VPN termination",
         420, 100, "fw-subnet", label_width=290)
    icon("fw2", "NVA2 | vm-cvpn-ew24-fw\n172.30.10.5 / eth0\nNO VPN termination",
         730, 100, "fw-subnet", label_width=290)
    vertex(root, "lb-policy", "INTERNAL LB / BACKEND POLICY\n"
           "ONE frontend / pool | floating IP | HA ports | TCP health 9999\n"
           "Two ALTERNATIVE backends — never serial firewalls",
           40, 70, 540, 125, "provider", size=20, fill="#edf6ff")
    vertex(root, "delivery-policy", "Delivery peering: useRemoteGateways ONLY toward PD.\n"
           "Firewall prefix UDRs removed; BGP propagation enabled.\n"
           "Both guests: default route only; no BGP/VPN daemon; no customer SNAT.",
           70, 1040, 550, 115, "provider", size=19, fill="#edf6ff")
    vertex(root, "update-egress", "UPDATE EGRESS ONLY | 2 Standard public IPs\n"
           "One per NVA NIC for own updates; SSH currently closed; user-opened TCP/22 (key-only).\n"
           "No extra NIC / NAT Gateway; not the customer inspection path.",
           40, 1200, 1020, 85, "provider", size=19, fill="#edf6ff")

    edge(root, "a-ingress", "vm-a", "ra", "1a | ingress peering + UDR", BLUE,
         ((1910, 420), (1910, 400)), dashed=True, anchors=(0, .5, 1, .5))
    edge(root, "b-ingress", "vm-b", "ra", "1b | ingress peering + UDR", BLUE,
         ((2250, 1300), (2250, 235), (1850, 235), (1850, 380)),
         dashed=True, anchors=(1, .5, 1, .25))
    edge(root, "ra-to-ci", "ra", "ci", "UDR", PURPLE, anchors=(0, .5, 1, .5))
    edge(root, "tunnel-1", "ci", "pi", "2 | IPsec ingress / UDP 500,4500", ORANGE, anchors=(0, .5, 1, .5))
    edge(root, "pi-to-lb", "pi", "lb", "3 | ingress peering\nTwo fixed /16 UDRs → LB VIP", PURPLE,
         ((170, 400),), anchors=(0, .5, .5, 0))
    edge(root, "lb-to-fw", "lb", "fw", "4a | OR", TEAL, anchors=(1, .3, 0, .3))
    edge(root, "lb-to-fw2", "lb", "fw2", "4b | OR", TEAL,
         ((300, 700), (840, 700)), anchors=(1, 0, .5, 0))
    edge(root, "fw-to-pd", "fw", "pd", "Gateway-propagated delivery", TEAL,
         ((700, 790), (700, 1100), (1090, 1100), (1090, 1200), (850, 1200)),
         anchors=(1, .7, .5, 0))
    edge(root, "fw2-to-pd", "fw2", "pd", "", TEAL,
         ((1000, 775), (1000, 1200), (850, 1200)), anchors=(1, .5, .5, 0))
    edge(root, "tunnel-2", "pd", "cd", "5 | IPsec delivery T2 / UDP 500,4500", ORANGE)
    vertex(root, "delivery-bgp", "DELIVERY CONTROL PLANE (over T2)\n"
           "CD ASN 65021 ↔ PD ASN 65031 | BGP TCP/179\n"
           "Prefix add / withdrawal verified; not a data-plane hop.",
           1220, 970, 650, 110, size=20, fill="#f3e5f5", stroke=PURPLE)
    edge(root, "delivery-a", "cd", "vm-a", "6a | delivery peering", BLUE,
         ((1880, 1260), (1880, 590), (2070, 590)), dashed=True, anchors=(1, .25, .5, 1))
    edge(root, "delivery-b", "cd", "vm-b", "6b | delivery peering", BLUE,
         ((1880, 1280), (1880, 1300)), dashed=True)
    vertex(root, "legend", "READING THE TOPOLOGY\n"
           "Blue dashed = customer peering; purple dotted = UDR steering.\n"
           "Orange = managed IPsec; teal = source-preserving forwarding.\n"
           "4 customer + 2 provider peerings, bidirectional; provider links use peering.\n"
           "No cross-side / direct A–B peering. Legacy jump omitted.",
           1170, 1500, 1100, 190, size=20)
    vertex(root, "evidence", "CURRENT BOUNDED EVIDENCE | EW-22 / EW-23 / EW-24\n"
           "448 fresh TCP outcomes: 384 original-source passes + 64 expected denials.\n"
           "Backend health withdrawal + sampled SYN symmetry passed.\n"
           "Simulator: 2 Ubuntu VMs, NOT Check Point VMSS / stateful failover.\n"
           "Ingress still fixed to two /16s — NOT full customer independence.",
           30, 1500, 1100, 190, size=20)
    save(ROOT / "architecture/ew18-managed-vpn-inspection.drawio", document)


def vertex(root, identifier, value, x, y, width, height, parent="1", fill="#ffffff",
           stroke="#aab8c2", size=16, dashed=False, border=2, image=False):
    size = max(size, 18)
    if image:
        x -= (80 - width) / 2
        y -= (80 - height) / 2
        width = height = 80
        style = (f"image;image={VM};aspect=fixed;html=0;whiteSpace=wrap;verticalLabelPosition=bottom;"
                 f"verticalAlign=top;align=center;fontFamily=Arial;fontSize={size};fontColor={INK};labelWidth=270;")
    else:
        style = (f"rounded=1;arcSize=3;html=0;whiteSpace=wrap;fontFamily=Arial;fontSize={size};"
                 f"fontColor={INK};fillColor={fill};strokeColor={stroke};strokeWidth={border};"
                 "verticalAlign=top;align=left;spacingTop=10;spacingLeft=10;"
                 + ("dashed=1;dashPattern=8 8;" if dashed else ""))
    cell = ET.SubElement(root, "mxCell", id=identifier, value=value, parent=parent, vertex="1", style=style)
    ET.SubElement(cell, "mxGeometry", x=str(x), y=str(y), width=str(width), height=str(height), **{"as": "geometry"})
    return cell


def port(root, identifier, value, x, y, width, height, parent, colour):
    cell = vertex(root, identifier, value, x, y, width, height, parent, fill="#ffffff", stroke=colour, size=14)
    update_style(cell, verticalAlign="middle", align="center", spacingTop=2, spacingLeft=2)
    return cell


def edge(root, identifier, source, target, value, colour, points=(), dashed=False,
         anchors=(1, .5, 0, .5), arrow=True):
    style = (f"edgeStyle=orthogonalEdgeStyle;rounded=1;arcSize=12;html=0;fontFamily=Arial;fontSize=18;"
             f"strokeColor={colour};fontColor={colour};strokeWidth={3 if colour == ORANGE else 2};"
             f"endArrow={'block' if arrow else 'none'};endFill=1;labelBackgroundColor=#ffffff;"
             f"exitX={anchors[0]};exitY={anchors[1]};entryX={anchors[2]};entryY={anchors[3]};"
             + ("dashed=1;dashPattern=2 5;" if colour == PURPLE else "dashed=1;dashPattern=8 5;" if dashed else ""))
    cell = ET.SubElement(root, "mxCell", id=identifier, value=value, parent="1",
                         edge="1", source=source, target=target, style=style)
    geometry = ET.SubElement(cell, "mxGeometry", relative="1", **{"as": "geometry"})
    if points:
        array = ET.SubElement(geometry, "Array", **{"as": "points"})
        for x, y in points:
            ET.SubElement(array, "mxPoint", x=str(x), y=str(y))


def make_ew21():
    document = ET.Element("mxfile", host="app.diagrams.net", version="24.0.0", type="device")
    diagram = ET.SubElement(document, "diagram", id="ew21-ubuntu-overlay", name="ARCHIVED EW-21 Ubuntu overlay")
    model = ET.SubElement(diagram, "mxGraphModel", dx="2000", dy="1300", grid="1", gridSize="10",
                          guides="1", tooltips="1", connect="1", arrows="1", fold="1", page="1",
                          pageScale="1", pageWidth="2000", pageHeight="1640", math="0", shadow="0")
    root = ET.SubElement(model, "root")
    ET.SubElement(root, "mxCell", id="0")
    ET.SubElement(root, "mxCell", id="1", parent="0")
    vertex(root, "title", "ARCHIVED EW-21 | Ubuntu + WireGuard | Not a deployment candidate", 30, 20, 1940, 65,
           stroke="#ffffff", size=27)
    vertex(root, "isolation", "ONE physical tenant / subscription; provider and customer below are logical roles.\n"
           "Thick outer boundaries = roles; shaded boxes = VNets; dashed boxes = subnets. No cross-side peering.",
           30, 95, 1940, 65, fill="#fff9cc", stroke="#d6b656", size=18)
    vertex(root, "provider", "FWaaS PROVIDER | logical lab role", 30, 180, 920, 1120,
           fill="#e6f2ff", stroke=BLUE, size=23, border=3)
    vertex(root, "customer", "FWaaS CUSTOMER | logical lab role", 990, 180, 980, 1120,
           fill="#fff4e6", stroke=ORANGE, size=23, border=3)

    vertex(root, "vnet-p", "Provider hub VNet | 10.202.0.0/16", 30, 75, 860, 1040, "provider", "#d9eaff")
    vertex(root, "wan-p", "wan | 10.202.10.0/24", 35, 70, 790, 200, "vnet-p", "#edf6ff", dashed=True)
    vertex(root, "router-p-card", "vm-overlay-p | Router | 3 Azure NICs + 2 WireGuard interfaces",
           20, 35, 750, 145, "wan-p", "#f7fbff", size=14, border=1)
    vertex(root, "router-p", "Ubuntu", 20, 45, 64, 64, "router-p-card", size=14, image=True)
    port(root, "p-inspect", "wg-inspect\n10.254.21.2", 120, 40, 250, 40, "router-p-card", ORANGE)
    port(root, "p-wan-nic", "vm-overlay-p | WAN NIC\n10.202.10.4", 120, 90, 250, 45,
         "router-p-card", BLUE)
    port(root, "p-deliver", "wg-deliver\n10.254.21.5", 430, 90, 250, 40, "router-p-card", ORANGE)
    vertex(root, "pre-p", "PRE | 10.202.20.0/24", 35, 305, 340, 280, "vnet-p", "#edf6ff", dashed=True)
    vertex(root, "post-p", "POST | 10.202.30.0/24", 425, 305, 400, 280, "vnet-p", "#edf6ff", dashed=True)
    port(root, "p-pre-nic", "vm-overlay-p | PRE NIC\n10.202.20.4", 30, 55, 280, 65, "pre-p", BLUE)
    port(root, "p-post-nic", "vm-overlay-p | POST NIC\n10.202.30.4", 30, 55, 320, 65, "post-p", BLUE)
    port(root, "fw-pre-nic", "vm-overlay-fw | PRE NIC\n10.202.20.5", 30, 185, 280, 65, "pre-p", TEAL)
    port(root, "fw-post-nic", "vm-overlay-fw | POST NIC\n10.202.30.5", 30, 185, 320, 65, "post-p", TEAL)
    vertex(root, "fw-card", "vm-overlay-fw | Plain firewall | 2 Azure NICs",
           35, 635, 790, 160, "vnet-p", "#e8f5f2", stroke=TEAL, size=20)
    firewall = vertex(root, "fw", "NO VPN", 25, 45, 64, 64, "fw-card", size=18, image=True)
    update_style(firewall, labelWidth=110)
    vertex(root, "fw-nic-summary",
           "PRE: nic-overlay-fw-0 | 10.202.20.5\n"
           "POST: nic-overlay-fw-1 | 10.202.30.5\n"
           "Both NICs belong to this VM; no tunnel interfaces.",
           140, 45, 620, 95, "fw-card", "#e8f5f2", stroke="#e8f5f2", size=18, border=0)
    vertex(root, "p-notes", "FIXED PROVIDER: RFC1918 private IPv4 coverage (not a customer allocation).\n"
           "PRE UDR -> firewall 10.202.20.5; POST UDR -> router 10.202.30.4.\n"
           "WG AllowedIPs 0.0.0.0/0; explicit service tables, not Internet default.\n"
           "No per-VNet provider route, NSG or WireGuard update.",
           35, 825, 790, 160, "vnet-p", "#f7fbff", size=16, border=1)

    vertex(root, "vnet-c", "Customer hub VNet | 10.201.0.0/16", 30, 75, 920, 500, "customer", "#ffead1")
    vertex(root, "wan-c", "wan / source ingress | 10.201.10.0/24", 30, 70, 860, 200,
           "vnet-c", "#fff7ed", dashed=True)
    vertex(root, "router-c-card", "vm-overlay-c | Ubuntu router | 2 NICs + 2 WireGuard interfaces",
           20, 35, 820, 145, "wan-c", "#fffaf4", size=14, border=1)
    port(root, "c-inspect", "wg-inspect\n10.254.21.1", 20, 40, 250, 40, "router-c-card", ORANGE)
    port(root, "c-deliver", "wg-deliver\n10.254.21.6", 20, 90, 250, 40, "router-c-card", ORANGE)
    port(root, "c-ingress-nic", "Workload ingress NIC\n10.201.10.4", 375, 40, 250, 40, "router-c-card", PURPLE)
    vertex(root, "router-c", "Ubuntu", 700, 45, 64, 64, "router-c-card", size=14, image=True)
    vertex(root, "post-c", "post / destination delivery | 10.201.20.0/24", 30, 320, 860, 130,
           "vnet-c", "#fff7ed", dashed=True)
    port(root, "c-post-nic", "7 | Customer delivery table\n10.201.20.4", 340, 45, 280, 55, "post-c", TEAL)
    for identifier in ("p-wan-nic", "p-pre-nic", "p-post-nic", "fw-pre-nic", "fw-post-nic",
                       "c-ingress-nic", "c-post-nic"):
        update_style(root.find(f"mxCell[@id='{identifier}']"),
                     shape="label", image=NIC, imageWidth=32, imageHeight=32,
                     imageAlign="left", imageVerticalAlign="middle", spacingLeft=42)
    update_style(root.find("mxCell[@id='p-wan-nic']"), spacingLeft=36)
    for role, x, prefix, ip in (("a", 60, "10.203.0.0/16", "10.203.0.4"),
                                ("b", 520, "10.204.0.0/16", "10.204.0.4")):
        vertex(root, "vnet-" + role, "Workload VNet " + role.upper() + " | " + prefix,
               x, 650, 400, 270, "customer", "#ffead1")
        vertex(root, "subnet-" + role, "lan | " + ip.rsplit(".", 1)[0] + ".0/24",
               20, 70, 360, 170, "vnet-" + role, "#fff7ed", dashed=True)
        vertex(root, "vm-" + role, "vm-overlay-" + role + "\n" + ip,
               60, 45, 64, 64, "subnet-" + role, size=15, image=True)
        port(root, "udr-" + role, ("1 | " if role == "a" else "") + "UDR: other /16\nnext hop\n10.201.10.4",
             180, 65, 150, 70, "subnet-" + role, PURPLE)

    edge(root, "peering-a", "vnet-c", "vnet-a", "VNet peering", BLUE,
         ((1204, 790), (1250, 790)), True, (.2, 1, .5, 0), False)
    edge(root, "peering-b", "vnet-c", "vnet-b", "VNet peering", BLUE,
         ((1756, 790), (1710, 790)), True, (.8, 1, .5, 0), False)
    edge(root, "source-udr", "udr-a", "c-ingress-nic", "", PURPLE,
         ((1325, 810), (1950, 810), (1950, 550), (1530, 550)), True, (.5, 0, .5, 1))
    edge(root, "c-pre", "c-ingress-nic", "c-inspect", "PBR 100", PURPLE, anchors=(0, .5, 1, .5))
    edge(root, "tunnel-1", "c-inspect", "p-inspect", "2 | WireGuard inspection / UDP 51820",
         ORANGE, anchors=(0, .5, 1, .5))
    edge(root, "p-pre", "p-inspect", "p-pre-nic", "3 | PBR 100",
         BLUE, ((220, 440), (220, 550), (455, 550), (455, 647.5)), anchors=(0, 1, 1, .5))
    edge(root, "to-firewall", "p-pre-nic", "fw-pre-nic", "PRE UDR", PURPLE, anchors=(.5, 1, .5, 0))
    edge(root, "fw-egress", "fw-pre-nic", "fw-post-nic", "4 | firewall inspection", TEAL,
         anchors=(1, .5, 0, .5))
    ET.SubElement(root.find("mxCell[@id='fw-egress']/mxGeometry"), "mxPoint",
                  x="0", y="-60", **{"as": "offset"})
    edge(root, "post-udr", "fw-post-nic", "p-post-nic", "POST UDR", PURPLE, anchors=(.5, 0, .5, 1))
    edge(root, "p-delivery", "p-post-nic", "p-deliver", "5 | PBR 200", TEAL,
         ((900, 640), (900, 550), (670, 550)), anchors=(1, .5, .5, 1))
    edge(root, "tunnel-2", "p-deliver", "c-deliver", "6 | WireGuard delivery / UDP 51821", ORANGE)
    edge(root, "c-delivery", "c-deliver", "c-post-nic", "PBR 200", TEAL,
         ((1215, 550), (1370, 550), (1370, 647)), anchors=(.5, 1, 0, .5))
    edge(root, "destination", "c-post-nic", "vm-b", "", TEAL,
         ((1530, 765), (1480, 765), (1480, 977)), anchors=(.5, 1, 0, .5))
    edge(root, "p-pre-owner", "router-p-card", "p-pre-nic", "", "#64748b",
         ((110, 500), (110, 630)), dashed=True, anchors=(0, .9, 0, .2), arrow=False)
    edge(root, "p-post-owner", "router-p-card", "p-post-nic", "", "#64748b",
         ((920, 500), (920, 628)), dashed=True, anchors=(1, .9, 1, .2), arrow=False)
    edge(root, "fw-pre-owner", "fw-card", "fw-pre-nic", "", "#64748b",
         dashed=True, anchors=(.2, 0, .5, 1), arrow=False)
    edge(root, "fw-post-owner", "fw-card", "fw-post-nic", "", "#64748b",
         dashed=True, anchors=(.8, 0, .5, 1), arrow=False)

    vertex(root, "legend", "LEGEND\nBlue dashed = ordinary peering; purple dotted = UDR / policy steering.\n"
           "Orange = encrypted transport; teal = post-inspection delivery.\n"
           "Grey dashed, no arrows = NIC ownership, NOT packet flow.\n"
           "NIC labels name their VM; router = 3 NICs, firewall = 2 NICs.",
           30, 1320, 940, 130, size=16)
    vertex(root, "reading", "READ THIS AS A -> B; B -> A AND RESPONSES USE THE SAME PIPELINE.\n"
           "4 VNets | 5 Ubuntu VMs | 9 NICs | 2 tunnels | original inner addresses.\n"
           "No Azure VPN gateways, cross-side peering or firewall VPN termination.\n"
           "ARM test management; manual SSH via routers, operator IPv4 /32 only.",
           990, 1320, 980, 130, size=16)
    vertex(root, "customer-lifecycle",
           "CUSTOMER LIFECYCLE TEST | 192.168.77.0/24 + workload VM: CREATED, TESTED, THEN REMOVED.\n"
           "Customer-only: peering + UDRs + delivery-table update; deleted prefix explicitly unreachable.\n"
           "24 original-source deliveries + 6 selective denials; removal/no-loop checks passed.\n"
           "CAVEAT: combined runs after DNS/shutdown interruption; audited redundant DHCP rule difference after reboot.\n"
           "Not an uninterrupted lifecycle or production multi-customer qualification; service/tunnel overlaps excluded.",
           30, 1470, 1940, 150, fill="#fff9cc", stroke="#d6b656", size=18)
    save(ROOT / "archive/prototypes/ew21-ubuntu-overlay.drawio", document)


def main():
    restyle_ew18()
    make_ew21()
    print("Prepared active EW-18 and archived historical EW-21 topologies; export locally with scripts/render_diagrams.py")


if __name__ == "__main__":
    main()
