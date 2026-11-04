#!/usr/bin/env python3
"""Export editable Draw.io diagrams locally as self-contained vector images."""

import argparse
import base64
import json
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SVG = "http://www.w3.org/2000/svg"
XLINK = "http://www.w3.org/1999/xlink"
VERIFIED_ICONS = {
    "img/lib/azure2/compute/Virtual_Machine.svg",
    "img/lib/azure2/containers/Container_Instances.svg",
    "img/lib/azure2/security/Key_Vaults.svg",
    "img/lib/azure2/networking/Virtual_Network_Gateways.svg",
    "img/lib/azure2/networking/Load_Balancers.svg",
    "img/lib/azure2/networking/Network_Interfaces.svg",
    "img/lib/azure2/networking/Virtual_Networks.svg",
    "img/lib/azure2/networking/Virtual_Router.svg",
    "img/lib/azure2/networking/Firewalls.svg",
    "img/lib/azure2/networking/Virtual_WAN_Hub.svg",
    "img/lib/azure2/other/Azure_Network_Manager.svg",
}
VECTOR_ELEMENTS = {
    "svg", "defs", "g", "path", "rect", "circle", "ellipse", "polygon", "polyline",
    "line", "linearGradient", "radialGradient", "stop", "clipPath", "title", "desc",
}
ET.register_namespace("", SVG)


def validate_source(path):
    document = ET.parse(path).getroot()
    graph = document.find("diagram/mxGraphModel/root")
    if document.tag != "mxfile" or len(document.findall("diagram")) != 1 or graph is None:
        raise ValueError("Draw.io source must have one uncompressed, inspectable diagram")
    cells = graph.findall("mxCell")
    ids = [cell.get("id") for cell in cells]
    if None in ids or len(ids) != len(set(ids)):
        raise ValueError("Draw.io cells require unique explicit IDs")
    for cell in cells:
        for key in ("parent", "source", "target"):
            if cell.get(key) is not None and cell.get(key) not in ids:
                raise ValueError("Draw.io cell references an unknown parent or endpoint")
        if cell.get("vertex") == "1" or cell.get("edge") == "1":
            if cell.find("mxGeometry[@as='geometry']") is None:
                raise ValueError("Draw.io geometry is incomplete")
        style = cell.get("style", "")
        images = re.findall(r"(?:^|;)image=([^;]+)", style)
        if any(image not in VERIFIED_ICONS for image in images):
            raise ValueError("Draw.io source uses an unverified image")
    return cells


def inline_icon(image, number):
    uri = image.get("href") or image.get("{" + XLINK + "}href", "")
    prefix = "data:image/svg+xml;" + "base64,"
    if not uri.startswith(prefix):
        raise ValueError("Native export contains an unresolved or non-SVG image")
    icon = ET.fromstring(base64.b64decode(uri[len(prefix):], validate=True))
    if icon.tag != "{" + SVG + "}svg":
        raise ValueError("Native icon is not SVG")
    if "viewBox" not in icon.attrib:
        dimensions = [icon.get(key, "") for key in ("width", "height")]
        if any(not re.fullmatch(r"\d+(?:\.\d+)?", value) or float(value) <= 0 for value in dimensions):
            raise ValueError("Native icon lacks usable vector dimensions")
        icon.set("viewBox", "0 0 " + " ".join(dimensions))
    for parent in list(icon.iter()):
        for child in list(parent):
            if child.tag in {"{http://sodipodi.sourceforge.net/DTD/sodipodi-0.dtd}namedview",
                             "{" + SVG + "}metadata"}:
                parent.remove(child)
    ids = {
        node.get("id"): f"icon-{number}-shape-{index}"
        for index, node in enumerate(node for node in icon.iter() if node.get("id"))
    }
    for node in icon.iter():
        if node.tag.removeprefix("{" + SVG + "}") not in VECTOR_ELEMENTS:
            raise ValueError("Native icon contains unexpected non-vector content")
        for key, value in list(node.attrib.items()):
            if key.startswith("{") and not key.startswith("{" + XLINK + "}"):
                del node.attrib[key]
                continue
            if key.lower().startswith("on") or "data:" in value:
                raise ValueError("Native icon contains active or nested encoded content")
            if key == "id":
                node.set(key, ids[value])
            else:
                for old, new in ids.items():
                    value = value.replace("url(#" + old + ")", "url(#" + new + ")")
                    if value == "#" + old:
                        value = "#" + new
                if key.endswith("href") and not value.startswith("#"):
                    raise ValueError("Native icon contains an external dependency")
                node.set(key, value)
    for key in ("x", "y", "width", "height", "transform", "opacity"):
        if image.get(key) is not None:
            icon.set(key, image.get(key))
    icon.set("preserveAspectRatio", "xMidYMid meet")
    return icon


def portable_svg(data):
    document = ET.fromstring(data)
    if document.tag != "{" + SVG + "}svg":
        raise ValueError("Draw.io did not export an SVG")
    number = 0
    for parent in list(document.iter()):
        for child in list(parent):
            if child.tag == "{" + SVG + "}switch":
                fallback = child.find("{" + SVG + "}text")
                if fallback is None and child.find("{" + SVG + "}foreignObject") is not None:
                    raise ValueError("Native export has no portable text fallback")
                index = list(parent).index(child)
                parent.remove(child)
                if fallback is not None:
                    parent.insert(index, fallback)
            elif child.tag == "{" + SVG + "}image":
                replacement = inline_icon(child, number)
                number += 1
                index = list(parent).index(child)
                parent.remove(child)
                parent.insert(index, replacement)
            elif child.tag == "{" + SVG + "}path" and "ge-flow-animation-" in child.get("style", ""):
                # Desktop exports reference keyframes they do not include in the SVG.
                declarations = [
                    item for item in child.get("style", "").split(";")
                    if item.strip() and item.split(":", 1)[0].strip() not in {"animation", "stroke-dashoffset"}
                ]
                child.set("style", ";".join(declarations))
                child.attrib.pop("stroke-dasharray", None)
                child.attrib.pop("stroke-dashoffset", None)
                dot = ET.SubElement(parent, "{" + SVG + "}circle", {
                    "r": "6", "fill": "#ffffff", "stroke": child.get("stroke", "#243746"),
                    "stroke-width": "2", "visibility": "hidden", "pointer-events": "none",
                })
                ET.SubElement(dot, "{" + SVG + "}set", {
                    "attributeName": "visibility", "to": "visible", "begin": "0s",
                })
                ET.SubElement(dot, "{" + SVG + "}animateMotion", {
                    "path": child.attrib["d"], "dur": "4s", "repeatCount": "indefinite",
                })
    for node in document.iter():
        if node.tag.endswith(("script", "foreignObject", "image")):
            raise ValueError("Export still contains active, HTML or unresolved image content")
        if any("data:" in value or (key.endswith("href") and not value.startswith("#"))
               for key, value in node.attrib.items()):
            raise ValueError("Export is not a self-contained vector image")
    ET.indent(document, space="  ")
    return ET.tostring(document, encoding="utf-8", xml_declaration=True)


def topology_detail_views(data):
    views = {}
    for name, bounds in (
        ("provider", (0, 120, 1165, 1282)),
        ("customer", (1210, 120, 1179, 1282)),
    ):
        document = ET.fromstring(data)
        document.set("viewBox", " ".join(map(str, bounds)))
        document.set("width", f"{bounds[2]}px")
        document.set("height", f"{bounds[3]}px")
        for cell_id in ("ingress-ipsec", "delivery-ipsec"):
            group = document.find(f".//*[@data-cell-id='{cell_id}']")
            text = group.find(".//{" + SVG + "}text")
            background = group.find(".//{" + SVG + "}rect")
            center = 1100 if name == "provider" else 1285
            text.set("x", str(center))
            background.set("x", str(center - float(background.get("width")) / 2))
        views[name] = ET.tostring(document, encoding="utf-8", xml_declaration=True)
    return views


def publication_sources(approved):
    sources = sorted((ROOT / "docs/diagrams").glob("*.drawio"))
    if len(sources) != 6:
        raise ValueError("Expected the six reviewed deployment diagrams")
    sources.extend(
        ROOT / path for path in sorted(approved)
        if path.startswith(("architecture/", "archive/prototypes/")) and path.endswith(".drawio")
    )
    return sources


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--drawio", help="Path to the installed Draw.io desktop executable")
    parser.add_argument("--source", type=Path, help="Export only this publication-approved Draw.io source")
    args = parser.parse_args()
    executable = args.drawio or shutil.which("drawio")
    if executable is None and sys.platform == "darwin":
        executable = "/Applications/draw.io.app/Contents/MacOS/draw.io"
    if executable is None or not Path(executable).is_file():
        raise RuntimeError("Draw.io desktop is required. Install it or supply --drawio /path/to/executable.")
    approved = set(json.loads((ROOT / "publication-manifest.json").read_text())["files"])
    sources = publication_sources(approved)
    if args.source:
        source = (ROOT / args.source).resolve()
        if source.relative_to(ROOT).as_posix() not in approved:
            raise ValueError("Requested Draw.io source is outside the publication manifest")
        sources = [source]
    with tempfile.TemporaryDirectory(prefix=".faas-drawio-export-", dir=ROOT) as temporary:
        for source in sources:
            validate_source(source)
            exported = Path(temporary) / (source.stem + ".svg")
            result = subprocess.run(
                [str(executable), "--disable-update", "--export", "--format", "svg",
                 "--embed-svg-images", "--embed-svg-fonts", "false", "--theme", "light",
                 "--output", str(exported), str(source)],
                capture_output=True, text=True, timeout=120,
            )
            if result.returncode or not exported.is_file():
                raise RuntimeError("Local Draw.io export failed for " + source.name)
            target = source.with_suffix(".svg")
            data = portable_svg(exported.read_bytes())
            target.write_bytes(data)
            print("Rendered:", target.relative_to(ROOT))
            if source.relative_to(ROOT).as_posix() == "architecture/working-lab-topology.drawio":
                for name, detail in topology_detail_views(data).items():
                    detail_target = target.with_name(f"{target.stem}-{name}.svg")
                    detail_target.write_bytes(detail)
                    print("Rendered:", detail_target.relative_to(ROOT))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError, ET.ParseError, subprocess.TimeoutExpired) as error:
        print("ERROR:", error, file=sys.stderr)
        sys.exit(1)
