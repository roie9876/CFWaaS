import contextlib
import base64
import io
import json
import os
import re
import stat
import sys
import tempfile
import unittest
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "archive/failed-scenarios/cross-tenant-nic-lab"))
import check_publication as publication
import render_diagrams
import generate_lab_topologies
import setup_local
from guest_tools import extract_guest_result, request_script, require_marker
from lab import AccountProfiles, Arm


def synthetic_accounts():
    return {
        "A": {"tenant": str(uuid.UUID(int=1)), "subscription": str(uuid.UUID(int=2))},
        "B": {"tenant": str(uuid.UUID(int=3)), "subscription": str(uuid.UUID(int=4))},
    }


def deployment_guides():
    allowed = publication.manifest_paths((ROOT / publication.MANIFEST).read_bytes())
    return sorted(
        (ROOT / path for path in allowed if re.search(r"(?:^|/)deployments/\d{2}-[^/]+/README\.md$", path)),
        key=lambda path: path.parent.name,
    )


class PublicationTests(unittest.TestCase):
    def test_allowed_worktree_is_clean(self):
        findings, count = publication.worktree_findings(ROOT)
        self.assertGreater(count, 40)
        self.assertEqual(findings, [], [(item.path, item.line, item.category) for item in findings])

    def test_manifest_cannot_approve_runtime_material(self):
        for path in (
            "results/evidence.json", ".local/accounts.json", "lab/.azure/plan.json",
            "lab/config.json", "lab/REPORT.md", "lab/private.pem", "lab/.env", "lab/.secrets.json",
        ):
            with self.subTest(path=path):
                self.assertTrue(publication.path_findings(path, {path}))

    def test_common_secret_shapes_are_blocked_without_exposing_content(self):
        samples = (
            "-----BEGIN " + "PRIVATE KEY-----",
            "-----BEGIN " + "CERTIFICATE-----",
            "gh" + "p_" + "A" * 36,
            "eyJ" + "a" * 20 + "." + "b" * 20 + "." + "c" * 20,
            "Account" + "Key=" + "Q" * 40,
            "?sig=" + "Q" * 40,
            "ssh-" + "ed25519 " + "A" * 48,
        )
        for sample in samples:
            with self.subTest(category=len(sample)):
                findings = publication.scan_content("README.md", sample.encode())
                self.assertTrue(findings)
                self.assertNotIn(sample, repr(findings))

    def test_public_provisioning_roles_are_not_private_identity_metadata(self):
        for role in (
            "0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3",
            "4633458b-17de-408a-b874-0445c86b69e6",
            "b86a8fe4-44ce-4948-aee5-eccb2c155cd7",
            "f1a07417-d97a-45cb-824c-7a7467783830",
            "ba92f5b4-2d11-453d-a403-e96b0029c9fe",
            "9980e02c-c2be-4d73-94e8-173b1dc7cf3c",
        ):
            with self.subTest(role=role):
                self.assertEqual(publication.scan_content("infra/main.bicep", role.encode()), [])
        self.assertTrue(publication.scan_content("infra/main.bicep", str(uuid.uuid4()).encode()))

    def test_identity_metadata_is_blocked_and_public_fixtures_are_allowed(self):
        private = (
            str(uuid.uuid4()), "person" + "@" + "company.invalid",
            "/" + "Users" + "/private-person/project/",
            "private-tenant" + ".onmicrosoft.com", "20.30." + "40.50",
            "20260101-" + "010101-abcdef",
        )
        for sample in private:
            with self.subTest(length=len(sample)):
                self.assertTrue(publication.scan_content("README.md", sample.encode()))
        for sample in (
            "10.1.0.0/16", "192.0.2.5", "0.0.0.0/0", "8.8.8.8",
            "100.64.0.0/10", "192.0.0.0/24", "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4",
            "192.88.99.0/24", "255.255.254.0", "255.255.255.0", "255.255.255.255",
            str(uuid.UUID(int=1)), "bot@users.noreply.github.com", "noreply@github.com",
        ):
            with self.subTest(sample=sample):
                self.assertEqual(publication.scan_content("README.md", sample.encode()), [])

    def test_public_readme_cannot_exempt_a_private_installer_subscription(self):
        private_id = str(uuid.uuid4())
        button = (
            "[![Deploy provider to Azure](https://aka.ms/deploytoazurebutton)]"
            "(https://portal.azure.com/#view/Microsoft_Azure_CreateUIDef/CustomDeploymentBlade/"
            "templateSpecVersionId/%2Fsubscriptions%2F" + private_id
            + "%2FresourceGroups%2Frg-faas-release-ew18-20260101"
            "%2Fproviders%2FMicrosoft.Resources%2FtemplateSpecs%2Ffaas-provider-setup"
            "%2Fversions%2F1.0)"
        )
        self.assertTrue(publication.scan_content("README.md", button.encode()))
        self.assertNotIn(private_id, repr(publication.scan_content("README.md", button.encode())))

    def test_checkpoint_vendor_ssh_placeholder_is_narrowly_scoped(self):
        placeholder = publication.CHECKPOINT_SSH_PATH
        line = f'path = "{placeholder}"'
        for path in publication.CHECKPOINT_SSH_PATH_FILES:
            with self.subTest(path=path):
                self.assertEqual(publication.scan_content(path, line.encode()), [])
                self.assertTrue(publication.scan_content(path, (line[:-1] + "-private\"").encode()))
        self.assertTrue(publication.scan_content("README.md", line.encode()))
        self.assertTrue(publication.scan_content(
            "provider-provisioning/service/checkpoint_plan.py",
            ("/" + "home" + "/private-user/.ssh/authorized_keys").encode()))

    def make_git_fixture(self, root):
        allowed = {"README.md", publication.MANIFEST}
        (root / publication.MANIFEST).write_text(json.dumps({"schemaVersion": 1, "files": sorted(allowed)}))
        (root / "README.md").write_text("Generic project\n")
        publication.git(root, "init", "-q")
        publication.git(root, "add", "--", *sorted(allowed))
        return allowed

    def test_staged_blobs_not_current_worktree_are_inspected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_git_fixture(root)
            token = "gh" + "p_" + "A" * 36
            (root / "README.md").write_text(token)
            publication.git(root, "add", "--", "README.md")
            (root / "README.md").write_text("Sanitized working copy\n")
            self.assertEqual(publication.worktree_findings(root)[0], [])
            self.assertTrue(any(item.category == "GitHub token" for item in publication.staged_findings(root)[0]))
            publication.git(root, "add", "--", "README.md")
            (root / "README.md").write_text(token)
            self.assertEqual(publication.staged_findings(root)[0], [])
            self.assertTrue(publication.worktree_findings(root)[0])

    def test_force_added_private_path_and_symlink_are_blocked(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_git_fixture(root)
            (root / "private.json").write_text("{}")
            publication.git(root, "add", "--", "private.json")
            self.assertTrue(any("allowlist" in item.category for item in publication.staged_findings(root)[0]))
            (root / "README.md").unlink()
            (root / "README.md").symlink_to(root / "private.json")
            publication.git(root, "add", "--", "README.md")
            self.assertTrue(any("non-regular" in item.category for item in publication.staged_findings(root)[0]))

    def test_history_catches_content_removed_from_latest_tree(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_git_fixture(root)
            (root / "README.md").write_text(str(uuid.uuid4()))
            publication.git(root, "add", "--", "README.md")
            identity = ("-c", "user.name=Fixture", "-c", "user.email=fixture@users.noreply.github.com")
            message = (
                "Fixture\n\nCo-authored-by: Copilot "
                "<223556219+Copilot@users.noreply.github.com>"
            )
            publication.git(root, *identity, "commit", "-qm", message)
            (root / "README.md").write_text("Generic project\n")
            publication.git(root, "add", "--", "README.md")
            publication.git(root, *identity, "commit", "-qm", message)
            self.assertEqual(publication.staged_findings(root)[0], [])
            findings, commits = publication.history_findings(root)
            self.assertEqual(commits, 2)
            self.assertTrue(any(item.category == "non-public identity UUID" for item in findings))

    def test_history_ignores_unpublished_checkpoint_but_checks_explicit_push(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_git_fixture(root)
            identity = ("-c", "user.name=Fixture", "-c", "user.email=fixture@users.noreply.github.com")
            trailer = "\n\nCo-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
            publication.git(root, *identity, "commit", "-qm", "Fixture" + trailer)
            head = publication.git(root, "rev-parse", "HEAD").decode().strip()
            tree = publication.git(root, "rev-parse", "HEAD^{tree}").decode().strip()
            checkpoint = publication.git(
                root, *identity, "commit-tree", tree, "-p", head,
                "-m", "Local checkpoint " + str(uuid.uuid4()) + trailer,
            ).decode().strip()
            publication.git(root, "update-ref", "refs/agents/fixture/checkpoint", checkpoint)
            self.assertEqual(publication.history_findings(root), ([], 1))
            zeros = "0" * 40
            outgoing = publication.push_revisions(f"refs/heads/main {head} refs/heads/main {zeros}\n")
            self.assertEqual(publication.history_findings(root, outgoing), ([], 1))
            outgoing = publication.push_revisions(
                f"refs/agents/fixture/checkpoint {checkpoint} refs/heads/published {zeros}\n",
            )
            findings, count = publication.history_findings(root, outgoing)
            self.assertEqual(count, 2)
            self.assertTrue(any(item.category == "non-public identity UUID" for item in findings))
            publication.git(root, "update-ref", "refs/heads/published", checkpoint)
            self.assertTrue(publication.history_findings(root)[0])
            publication.git(root, "update-ref", "-d", "refs/heads/published")
            publication.git(root, "update-ref", "refs/tags/published", checkpoint)
            self.assertTrue(publication.history_findings(root)[0])

    def test_pre_push_rejects_invalid_input_and_skips_deletions(self):
        zeros = "0" * 40
        existing = "a" * 40
        self.assertEqual(publication.push_revisions(""), [])
        self.assertEqual(
            publication.push_revisions(f"(delete) {zeros} refs/heads/old {existing}\n"), [],
        )
        self.assertEqual(publication.history_findings(ROOT, []), ([], 0))
        for value in ("invalid", f"refs/heads/main --all refs/heads/main {zeros}"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                publication.push_revisions(value)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_git_fixture(root)
            self.assertEqual(publication.history_findings(root), ([], 0))

    def test_push_hook_checks_outgoing_history_without_bypassing_scanner(self):
        hook = (ROOT / ".githooks/pre-push").read_text()
        self.assertIn("--staged --history --pre-push", hook)
        self.assertNotIn("--no-verify", hook)

    def test_relative_markdown_links_target_published_files(self):
        allowed = publication.manifest_paths((ROOT / publication.MANIFEST).read_bytes())
        for path in sorted(allowed):
            if not path.endswith(".md"):
                continue
            text = (ROOT / path).read_text()
            for target in re.findall(r"\]\(([^)]+)\)", text):
                target = target.strip("<>").split("#", 1)[0]
                if not target or "://" in target or target.startswith("mailto:"):
                    continue
                resolved = ((ROOT / path).parent / target).resolve()
                self.assertTrue(resolved.exists(), (path, target))
                relative = resolved.relative_to(ROOT).as_posix()
                self.assertTrue(
                    relative in allowed or any(item.startswith(relative.rstrip("/") + "/") for item in allowed),
                    (path, target, "link only exists in private local workspace"),
                )

    def test_every_option_diagram_marks_all_tenant_boundaries(self):
        options = deployment_guides()
        self.assertEqual(len(options), 6)
        for path in options:
            text = path.read_text()
            stem = path.parent.name
            relative = os.path.relpath(ROOT / "docs/diagrams", path.parent).replace(os.sep, "/")
            self.assertIn(f"{relative}/{stem}.svg", text)
            self.assertIn(f"{relative}/{stem}.drawio", text)
            self.assertIn(f"https://github.com/roie9876/CFWaaS/raw/refs/heads/main/docs/diagrams/{stem}.svg", text)
            self.assertNotIn("```mermaid", text)
            self.assertIn("**Status:**", text)
            self.assertEqual(text.count("```") % 2, 0)

    def test_main_readme_embeds_only_active_ew18_topology_at_full_width(self):
        text = (ROOT / "docs/ew18-historical-readme.md").read_text()
        for heading, name in (
            ("EW-18 managed VPN gateways", "ew18-managed-vpn-inspection"),
        ):
            with self.subTest(lab=name):
                section = text.split("## " + heading + "\n", 1)[1].split("\n## ", 1)[0]
                path = "architecture/" + name + ".svg"
                full_size = "https://github.com/roie9876/CFWaaS/raw/refs/heads/main/" + path
                blocks = re.findall(r"<a\b[^>]*>\s*<img\b[^>]*?/>\s*</a>", section)
                self.assertEqual(len(blocks), 1)
                link = ET.fromstring(blocks[0])
                image = link.find("img")
                self.assertEqual(link.get("href"), full_size)
                self.assertEqual(image.get("src"), "../" + path)
                self.assertTrue(image.get("alt"))
                source = ET.parse(ROOT / path).getroot()
                width = int(source.get("width").removesuffix("px"))
                self.assertGreaterEqual(width, 1900)
                self.assertEqual(int(image.get("width")), width)
                self.assertIn(f"]({full_size})", section)
                self.assertIn(f"](../{path.removesuffix('.svg')}.drawio)", section)
                self.assertIn("**How to read this topology:**", section)

        self.assertEqual(len(re.findall(r"<img\b", text)), 1)
        self.assertIn("only active deployment candidate", text)
        self.assertIn("archive/prototypes/ew21-ubuntu-overlay.md", text)
        self.assertIn("not a deployment candidate", text)
        self.assertNotIn("Option 2: EW-21", text)
        self.assertNotIn("ew21-ubuntu-overlay.svg", text)
        ssh = text.split("## Connect to the lab VMs with SSH\n", 1)[1].split("\n## ", 1)[0]
        self.assertNotIn("EW21", ssh)
        self.assertNotIn("ew21-", ssh)
        for alias in ("ew18-nva1", "ew18-nva2", "ew18-a", "ew18-b"):
            self.assertIn(f'ssh -F "$SSH_CONFIG" {alias}', ssh)

    def test_public_guide_has_portable_setup_and_clear_roles(self):
        text = (ROOT / "README.md").read_text()
        guide = (ROOT / "docs/getting-started.md").read_text()
        self.assertIn("# CFWaaS", text)
        self.assertIn("docs/getting-started.md", text)
        self.assertNotIn("templateSpecVersionId/", text)
        self.assertNotIn("roie9876/faas", text)
        self.assertIn("https://github.com/roie9876/CFWaaS.git", text)
        for required in ("separate tenants and subscriptions", "Reveal credential",
                         "not production-ready", "not VMSS", "30 seconds"):
            self.assertIn(required, text)
        for required in ("Prerequisites", "Entra", "MFA", "EncryptionAtHost",
                         "Graph", "BYOL", "SSH public key", "budget",
                         "provider-owned", "Template Spec", "setupUrl",
                         "managementUrl", "Check setup readiness", "Sign in and review",
                         "do not need local Python or CLI", "customer API credential",
                         "VirtualAppliance", "routingAppliancePrivateIp", "30 seconds",
                         "not a ready-made public installer", "does not manage one"):
            self.assertIn(required.lower(), guide.lower())
        self.assertNotIn("python scripts/", text)
        self.assertNotIn("az login", text)

    def test_ew21_archive_preserves_results_recovery_caveats_and_ssh(self):
        guide = (ROOT / "archive/prototypes/ew21-ubuntu-overlay.md").read_text()
        self.assertTrue(guide.startswith(
            "> Archived by user decision 2026-10-26; not deployment candidate; "
            "historical measurements preserved; repository archive does not delete Azure resources\n"
        ))
        for content in (
            "**Result: passed and retained.**", "**42 successful deliveries**",
            "**24 expected denials**", "On 2026-10-26, manual ping and HTTP failed",
            "Deliberate networkd restarts", "not one uninterrupted lifecycle",
            "redundant provider-router DHCP", "source .local/lab-ssh.env",
            'export SSH_CONFIG="$EW21_SSH_CONFIG"',
            "](ew21-ubuntu-overlay.svg)", "](ew21-ubuntu-overlay.drawio)",
            "](../../docs/ew18-managed-vpn.md)", "](../../README.md)",
        ):
            self.assertIn(content, guide)
        for alias in ("ew21-customer", "ew21-provider", "ew21-fw", "ew21-a", "ew21-b"):
            self.assertIn(f'ssh -F "$SSH_CONFIG" {alias}', guide)
        index = (ROOT / "archive/prototypes/README.md").read_text()
        for target in ("ew17-firewall-terminated-ipsec.md", "ew21-ubuntu-overlay.md"):
            self.assertIn(f"]({target})", index)
        self.assertIn("not failed", index)
        self.assertIn("does not delete Azure resources", index)
        self.assertFalse((ROOT / "docs/ew21-ubuntu-overlay.md").exists())
        self.assertFalse((ROOT / "architecture/ew21-ubuntu-overlay.drawio").exists())
        self.assertFalse((ROOT / "architecture/ew21-ubuntu-overlay.svg").exists())
        source = ROOT / "archive/prototypes/ew21-ubuntu-overlay.drawio"
        cells = {cell.get("id"): cell for cell in render_diagrams.validate_source(source)}
        self.assertIn("ARCHIVED EW-21", cells["title"].get("value"))
        self.assertIn("Not a deployment candidate", cells["title"].get("value"))
        labels = " ".join(ET.parse(source.with_suffix(".svg")).getroot().itertext())
        self.assertIn("ARCHIVED EW-21", labels)

    def test_default_renderer_includes_only_reviewed_topology_directories(self):
        approved = publication.manifest_paths((ROOT / publication.MANIFEST).read_bytes())
        archived = "archive/prototypes/ew21-ubuntu-overlay.drawio"
        self.assertIn(ROOT / archived, render_diagrams.publication_sources(approved))
        extra = {
            "archive/failed-scenarios/unreviewed.drawio",
            "private/unreviewed.drawio",
            "archive/prototypes/unreviewed.svg",
        }
        sources = render_diagrams.publication_sources(approved | extra)
        self.assertTrue(all(ROOT / path not in sources for path in extra))
        self.assertNotIn(
            ROOT / archived, render_diagrams.publication_sources(approved - {archived}),
        )

    def test_historical_option_numbering_survives_archive(self):
        stems = ("01-direct-peering-controller", "02-direct-peering-avnm")
        options = deployment_guides()
        self.assertEqual(tuple(path.parent.name for path in options[:2]), stems)
        for number, stem in enumerate(stems, 1):
            guide = next(path for path in options if path.parent.name == stem).read_text()
            self.assertTrue(guide.startswith(f"# Option {number}:"))
            source = ET.parse(ROOT / "docs/diagrams" / (stem + ".drawio")).getroot().find("diagram")
            self.assertEqual(source.get("id"), stem)
            self.assertEqual(source.get("name"), stem)
        for path in ("docs/architecture.md", "docs/diagrams/README.md"):
            text = (ROOT / path).read_text()
            self.assertLess(text.index(stems[0]), text.index(stems[1]))

    def test_main_readme_shows_only_working_lab_figures(self):
        main = (ROOT / "README.md").read_text()
        topology = main.split("## Architecture\n", 1)[1].split("\n## Before spending money", 1)[0]
        self.assertIn("architecture/working-lab-topology.svg", topology)
        self.assertIn("architecture/working-lab-topology.drawio", topology)
        self.assertIn("architecture/working-lab-topology-provider.svg", topology)
        self.assertIn("architecture/working-lab-topology-customer.svg", topology)
        self.assertNotIn("```mermaid", topology)
        for unrelated in ("docs/diagrams/", "archive/prototypes/", "provider-bgp-peers",
                          "ew18-managed-vpn-inspection"):
            self.assertNotIn(unrelated, topology)
        self.assertIn("not allocation", topology)
        self.assertIn("not supported automatically", topology)
        self.assertIn("No production fail-closed", main)

    def test_working_lab_topology_matches_verified_components(self):
        source = ROOT / "architecture/working-lab-topology.drawio"
        cells = {cell.get("id"): cell for cell in render_diagrams.validate_source(source)}
        gateways = [cell for cell in cells.values()
                    if "image=img/lib/azure2/networking/Virtual_Network_Gateways.svg;" in cell.get("style", "")]
        self.assertEqual(len(gateways), 4)
        for identifier in ("route-server-ingress", "routing-appliance", "checkpoint-gateway",
                           "checkpoint-management", "provisioning-runner", "private-vault",
                           "workload-a", "workload-b"):
            self.assertIn(identifier, cells)
        for removed in ("load-balancer", "nva-0", "nva-1"):
            self.assertNotIn(removed, cells)
        self.assertNotIn("route-server-delivery", cells)
        self.assertNotIn("pd-route-subnet", cells)
        self.assertNotIn("provider-ingress-to-lb", cells)
        self.assertNotIn("bgp-delivery", cells)
        self.assertNotIn("bgp-delivery-gateway", cells)
        for identifier, endpoints in (
            ("ingress-ipsec", ("customer-ingress-gw", "provider-ingress-gw")),
            ("delivery-ipsec", ("provider-delivery-gw", "customer-delivery-gw")),
            ("provider-ingress-to-gateway", ("provider-ingress-gw", "checkpoint-gateway")),
            ("gateway-to-delivery", ("checkpoint-gateway", "provider-delivery-gw")),
            ("bgp-ingress", ("checkpoint-gateway", "route-server-ingress")),
            ("management-to-gateway", ("checkpoint-management", "checkpoint-gateway")),
            ("bgp-ingress-gateway", ("route-server-ingress", "provider-ingress-gw")),
        ):
            self.assertEqual((cells[identifier].get("source"), cells[identifier].get("target")), endpoints)
            if identifier.startswith("bgp-"):
                self.assertIn("dashed=1", cells[identifier].get("style"))
        self.assertIn("image=img/lib/azure2/networking/Virtual_Router.svg;",
                      cells["route-server-ingress"].get("style"))
        self.assertIn("image=img/lib/azure2/networking/Firewalls.svg;", cells["checkpoint-gateway"].get("style"))
        self.assertEqual(cells["checkpoint-management"].get("parent"), "management-subnet")
        self.assertEqual(cells["internet"].get("parent"), "1")
        self.assertIn("BGP-learned default to the Check Point gateway", cells["provider-routing-note"].get("value"))
        self.assertIn("Ingress IPsec: static", cells["provider-routing-note"].get("value"))
        self.assertEqual(cells["delivery-ipsec"].get("value"), "IPsec + BGP")
        self.assertIn("No Route Server", cells["delivery-routing-note"].get("value"))
        self.assertIn("Customer prefixes learned via BGP", cells["delivery-routing-note"].get("value"))
        self.assertIn("VPN default site: /0", cells["delivery-routing-note"].get("value"))
        self.assertIn("ASN 65031", cells["provider-delivery-gw"].get("value"))
        self.assertIn("ASN 65021", cells["customer-delivery-gw"].get("value"))
        self.assertIn("Check Point is a lab preview", cells["limits"].get("value"))
        self.assertIn("customer traffic pending", cells["limits"].get("value"))
        self.assertIn("fail-closed behavior is not established", cells["limits"].get("value"))
        labels = " ".join(cell.get("value", "") for cell in cells.values())
        self.assertNotRegex(labels, r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        image = ET.parse(source.with_suffix(".svg")).getroot()
        self.assertFalse(any(node.tag.endswith(("}image", "}script", "}foreignObject")) for node in image.iter()))
        rendered = " ".join(" ".join(node.itertext()) for node in image.iter() if node.tag.endswith("}text"))
        for label in ("Provider ingress", "Provider delivery", "Customer ingress", "Customer delivery",
                      "Azure Route Server", "Managed Routing Appliance", "Check Point CloudGuard",
                      "Check Point Security"):
            self.assertIn(label, rendered)
        self.assertNotRegex(rendered, r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        for name, detail in render_diagrams.topology_detail_views(source.with_suffix(".svg").read_bytes()).items():
            self.assertEqual(source.with_name(f"{source.stem}-{name}.svg").read_bytes(), detail)
            detail_image = ET.fromstring(detail)
            left, _, width, _ = map(float, detail_image.get("viewBox").split())
            self.assertLess(width, float(image.get("viewBox").split()[2]) / 2)
            for cell_id in ("ingress-ipsec", "delivery-ipsec"):
                group = detail_image.find(f".//*[@data-cell-id='{cell_id}']")
                background = group.find(".//{http://www.w3.org/2000/svg}rect")
                label_left = float(background.get("x"))
                self.assertGreaterEqual(label_left, left)
                self.assertLessEqual(label_left + float(background.get("width")), left + width)

    def test_working_lab_routing_preserves_routes_addresses_and_flow_types(self):
        source = ROOT / "architecture/working-lab-routing.drawio"
        cells = {cell.get("id"): cell for cell in render_diagrams.validate_source(source)}
        labels = " ".join(cell.get("value", "") for cell in cells.values())
        self.assertLessEqual(len(labels.split()), 250, "Keep the routing overview concise")
        for identifier, required in (
            ("workload-a-routes", ("10.211.0.4", "/0 + 10.212.0.0/16", "-> 172.18.10.4")),
            ("workload-b-routes", ("10.212.0.4", "/0 + 10.211.0.0/16", "-> 172.18.10.4")),
            ("ra-routes", ("172.18.10.4", "UDR: /0 + customer /16s", "-> ingress VPN gateway")),
            ("pi-routes", ("BGP /0 -> 172.22.10.4", "UDR table: empty")),
            ("firewall-routes", ("172.22.20.4", "UDR: /0 -> Internet", "Azure BGP: /16s -> delivery")),
            ("rs-routes", ("172.20.254.4 / .5", "Receives only /0")),
            ("pd-routes", ("172.21.255.30", "AS 65031", "BGP: customer /16s")),
            ("cd-routes", ("172.19.255.30", "AS 65021", "Advertises customer /16s")),
            ("evidence", ("effective-route queries denied",)),
        ):
            for value in required:
                self.assertIn(value, cells[identifier].get("value"))
        for identifier, parent in (
            ("routing-appliance", "ra-card"), ("workload-a", "a-card"),
            ("checkpoint-gateway", "fw-card"), ("customer-delivery-gw", "cd-card"),
        ):
            self.assertEqual(cells[identifier].get("parent"), parent)
        main = (ROOT / "README.md").read_text()
        self.assertIn("architecture/working-lab-routing.svg", main)
        self.assertIn("architecture/working-lab-routing.drawio", main)
        self.assertIn("EW-44", main)
        svg = ET.parse(source.with_suffix(".svg")).getroot()
        rendered = " ".join(" ".join(node.itertext()) for node in svg.iter()
                            if node.tag.endswith("}text"))
        for cell in cells.values():
            for line in cell.get("value", "").splitlines():
                self.assertIn(line.strip(), rendered, cell.get("id"))
            if cell.get("vertex") == "1" and cell.get("parent") != "1":
                geometry = cell.find("mxGeometry")
                parent = cells[cell.get("parent")].find("mxGeometry")
                for position, extent in (("x", "width"), ("y", "height")):
                    self.assertGreaterEqual(float(geometry.get(position)), 0)
                    self.assertLessEqual(float(geometry.get(position)) + float(geometry.get(extent)),
                                         float(parent.get(extent)))
        animated = [cell.get("id") for cell in cells.values()
                    if "flowAnimation=1;" in cell.get("style", "")]
        self.assertEqual(len(animated), 9)
        for identifier in animated:
            group = svg.find(f".//*[@data-cell-id='{identifier}']")
            self.assertIsNotNone(group.find(".//{" + render_diagrams.SVG + "}animateMotion"))
        for identifier in ("bgp-default-advertisement", "bgp-rs-to-pi", "delivery-bgp"):
            self.assertIn("dashed=1", cells[identifier].get("style"))
            self.assertNotIn(identifier, animated)
        self.assertIn("NO BGP", cells["ingress-ipsec"].get("value"))
        self.assertEqual((cells["b-to-ra"].get("source"), cells["b-to-ra"].get("target")),
                         ("b-card", "ra-card"))
        self.assertFalse(any(node.tag.endswith(("}image", "}script", "}foreignObject"))
                         for node in svg.iter()))

    def test_portable_flow_animation_has_solid_paths_and_self_contained_motion(self):
        source = (
            '<svg xmlns="http://www.w3.org/2000/svg"><g><path d="M 10 20 L 30 40" '
            'stroke="#00897b" stroke-dasharray="8" '
            'style="stroke: #00897b; animation: 500ms linear infinite ge-flow-animation-test; '
            'stroke-dashoffset: 16;"/></g></svg>'
        )
        svg = ET.fromstring(render_diagrams.portable_svg(source.encode()))
        path = svg.find(".//{" + render_diagrams.SVG + "}path")
        self.assertNotIn("animation", path.get("style"))
        self.assertNotIn("stroke-dasharray", path.attrib)
        motion = svg.find(".//{" + render_diagrams.SVG + "}animateMotion")
        self.assertEqual(motion.get("path"), path.get("d"))
        self.assertEqual(motion.get("repeatCount"), "indefinite")
        self.assertEqual(svg.find(".//{" + render_diagrams.SVG + "}circle").get("visibility"), "hidden")

    def test_verified_icon_editor_metadata_is_not_rendered(self):
        icon = ('<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10">'
                '<metadata><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"/>'
                '</metadata><path d="M0 0 L10 10"/></svg>')
        encoded = base64.b64encode(icon.encode()).decode()
        source = ('<svg xmlns="http://www.w3.org/2000/svg">'
                  '<image href="data:image/svg+xml;' + 'base64,' + encoded + '"/></svg>')
        rendered = ET.fromstring(render_diagrams.portable_svg(source.encode()))
        self.assertTrue(any(node.tag.endswith("}path") for node in rendered.iter()))
        self.assertFalse(any(node.tag.endswith(("}metadata", "}RDF")) for node in rendered.iter()))

    def test_managed_ipsec_topology_has_dual_peering_and_alternative_lb_backends(self):
        source = ROOT / "architecture/ew18-managed-vpn-inspection.drawio"
        cells = render_diagrams.validate_source(source)
        by_id = {cell.get("id"): cell for cell in cells}
        gateways = [c for c in cells if "image=img/lib/azure2/networking/Virtual_Network_Gateways.svg;" in c.get("style", "")]
        self.assertEqual(len(gateways), 4)
        for identifier, hostname, address in (
            ("fw", "vm-cvpn-ew18-fw", "172.30.10.4"),
            ("fw2", "vm-cvpn-ew24-fw", "172.30.10.5"),
        ):
            self.assertIn("NO VPN termination", by_id[identifier].get("value"))
            self.assertIn(hostname, by_id[identifier].get("value"))
            self.assertIn(address, by_id[identifier].get("value"))
            self.assertEqual(by_id[identifier].get("parent"), "fw-subnet")
        self.assertEqual(sum("image=img/lib/azure2/compute/Virtual_Machine.svg;" in c.get("style", "")
                             for c in cells), 4)
        self.assertEqual(sum("image=img/lib/azure2/networking/Load_Balancers.svg;" in c.get("style", "")
                             for c in cells), 1)
        self.assertEqual(by_id["lb"].get("parent"), "fw-subnet")
        self.assertIn("172.30.10.0/24", by_id["fw-subnet"].get("value"))
        self.assertIn("172.30.10.10", by_id["lb"].get("value"))
        self.assertIn("floating IP | HA ports | TCP health 9999", by_id["lb-policy"].get("value"))
        self.assertIn("ALTERNATIVE backends", by_id["lb-policy"].get("value"))
        expected_edges = {
            "ra-to-ci": ("ra", "ci"), "tunnel-1": ("ci", "pi"),
            "pi-to-lb": ("pi", "lb"), "lb-to-fw": ("lb", "fw"),
            "lb-to-fw2": ("lb", "fw2"), "fw-to-pd": ("fw", "pd"),
            "fw2-to-pd": ("fw2", "pd"), "tunnel-2": ("pd", "cd"),
            "a-ingress": ("vm-a", "ra"), "b-ingress": ("vm-b", "ra"),
            "delivery-a": ("cd", "vm-a"), "delivery-b": ("cd", "vm-b"),
        }
        actual_edges = {c.get("id"): (c.get("source"), c.get("target"))
                        for c in cells if c.get("edge") == "1"}
        self.assertEqual(actual_edges, expected_edges, "No serial firewall or inspection-bypass edge")
        self.assertIn("Two fixed /16 UDRs", by_id["pi-to-lb"].get("value"))
        self.assertIn("useRemoteGateways ONLY toward PD", by_id["delivery-policy"].get("value"))
        self.assertIn("BGP propagation enabled", by_id["delivery-policy"].get("value"))
        self.assertIn("no customer SNAT", by_id["delivery-policy"].get("value"))
        bgp = by_id["delivery-bgp"]
        self.assertEqual(bgp.get("vertex"), "1", "BGP annotation must not be a forwarding hop")
        self.assertIn("CONTROL PLANE (over T2)", bgp.get("value"))
        self.assertIn("CD ASN 65021 ↔ PD ASN 65031", bgp.get("value"))
        self.assertIn("2 Standard public IPs", by_id["update-egress"].get("value"))
        self.assertIn("SSH currently closed", by_id["update-egress"].get("value"))
        self.assertEqual(sum("image=img/lib/azure2/networking/Virtual_Router.svg;" in c.get("style", "") for c in cells), 1)
        def side(identifier):
            while identifier not in {"customer", "provider", "0", "1", None}:
                identifier = by_id[identifier].get("parent")
            return identifier
        cross = set()
        for cell in cells:
            if cell.get("edge") == "1" and side(cell.get("source")) != side(cell.get("target")):
                cross.add(cell.get("id"))
        self.assertEqual(cross, {"tunnel-1", "tunnel-2"})
        for identifier in ("a-ingress", "b-ingress", "delivery-a", "delivery-b"):
            edge = by_id[identifier]
            self.assertEqual(side(edge.get("source")), "customer")
            self.assertEqual(side(edge.get("target")), "customer")
        image = ET.parse(source.with_suffix(".svg")).getroot()
        self.assertFalse(any(node.tag.endswith(("}image", "}script", "}foreignObject")) for node in image.iter()))
        labels = " ".join(" ".join(node.itertext()) for node in image.iter() if node.tag.endswith("}text"))
        for text in ("NO VPN termination", "172.30.10.4", "172.30.10.5", "172.30.10.10",
                     "vm-cvpn-ew18-fw", "vm-cvpn-ew24-fw", "ALTERNATIVE backends",
                     "CONTROL PLANE", "CD ASN 65021", "PD ASN 65031", "2 Standard public IPs",
                     "384 original-source passes + 64 expected denials", "NOT full customer independence",
                     "1a | ingress peering", "1b | ingress peering",
                     "6a | delivery peering", "6b | delivery peering"):
            self.assertIn(text, labels)
        def centre(identifier):
            cell = by_id[identifier]
            geometry = cell.find("mxGeometry")
            x = float(geometry.get("x", "0")) + float(geometry.get("width", "0")) / 2
            y = float(geometry.get("y", "0")) + float(geometry.get("height", "0")) / 2
            parent = cell.get("parent")
            while parent not in {"0", "1", None}:
                cell = by_id[parent]
                geometry = cell.find("mxGeometry")
                x += float(geometry.get("x", "0"))
                y += float(geometry.get("y", "0"))
                parent = cell.get("parent")
            return x, y
        for customer, provider, tunnel in (("ci", "pi", "tunnel-1"), ("cd", "pd", "tunnel-2")):
            cx, cy = centre(customer)
            px, py = centre(provider)
            self.assertLess(px, cx, "Reference style places the blue provider left of the orange customer")
            self.assertEqual(cy, py, "VPN gateway pairs must face each other on the same row")
            self.assertIsNone(by_id[tunnel].find("mxGeometry/Array"), "IPsec links must be straight")

    def test_lab_generators_are_idempotent_and_match_sources(self):
        for generate, path in (
            (generate_lab_topologies.restyle_ew18, "architecture/ew18-managed-vpn-inspection.drawio"),
            (generate_lab_topologies.make_ew21, "archive/prototypes/ew21-ubuntu-overlay.drawio"),
        ):
            generated = []
            def capture(path, document):
                ET.indent(document, space="  ")
                generated.append((path, ET.tostring(document, encoding="utf-8", xml_declaration=True)))
            with patch.object(generate_lab_topologies, "save", side_effect=capture):
                generate()
                generate()
            self.assertEqual(generated[0], generated[1])
            self.assertEqual(generated[0][0], ROOT / path)
            self.assertEqual(generated[0][1], generated[0][0].read_bytes())

    def test_ubuntu_overlay_topology_has_five_vms_four_vnets_and_two_tunnels(self):
        source = ROOT / "archive/prototypes/ew21-ubuntu-overlay.drawio"
        cells = {cell.get("id"): cell for cell in render_diagrams.validate_source(source)}
        icons = [c for c in cells.values() if "image=img/lib/azure2/compute/Virtual_Machine.svg;" in c.get("style", "")]
        self.assertEqual(len(icons), 5)
        nic_icons = {identifier for identifier, cell in cells.items()
                     if "image=img/lib/azure2/networking/Network_Interfaces.svg;" in cell.get("style", "")}
        self.assertEqual(nic_icons, {"p-wan-nic", "p-pre-nic", "p-post-nic", "fw-pre-nic",
                                     "fw-post-nic", "c-ingress-nic", "c-post-nic"})
        for identifier in nic_icons:
            self.assertIn("shape=label;", cells[identifier].get("style", ""))
        for identifier in ("p-inspect", "p-deliver", "c-inspect", "c-deliver"):
            self.assertNotIn("image=", cells[identifier].get("style", ""))
        self.assertFalse(any("Virtual_Network_Gateways.svg" in c.get("style", "") for c in cells.values()))
        self.assertEqual({k for k in cells if k.startswith("vnet-")}, {"vnet-a", "vnet-b", "vnet-c", "vnet-p"})
        self.assertIn("NO VPN", cells["fw"].get("value"))
        self.assertIn("ONE physical tenant", cells["isolation"].get("value"))
        def side(identifier):
            while identifier not in {"customer", "provider", "0", "1", None}:
                identifier = cells[identifier].get("parent")
            return identifier
        cross = {c.get("id") for c in cells.values() if c.get("edge") == "1"
                 and side(c.get("source")) != side(c.get("target"))}
        self.assertEqual(cross, {"tunnel-1", "tunnel-2"})
        self.assertIn("51820", cells["tunnel-1"].get("value"))
        self.assertIn("51821", cells["tunnel-2"].get("value"))
        for name in ("peering-a", "peering-b"):
            self.assertEqual(side(cells[name].get("source")), "customer")
            self.assertEqual(side(cells[name].get("target")), "customer")
        for cell in cells.values():
            if cell.get("vertex") != "1" or cell.get("parent") == "1":
                continue
            geometry = cell.find("mxGeometry")
            parent = cells[cell.get("parent")].find("mxGeometry")
            for axis, extent in (("x", "width"), ("y", "height")):
                self.assertGreaterEqual(float(geometry.get(axis)), 0)
                self.assertLessEqual(float(geometry.get(axis)) + float(geometry.get(extent)),
                                     float(parent.get(extent)), cell.get("id"))
        image = ET.parse(source.with_suffix(".svg")).getroot()
        self.assertFalse(any(node.tag.endswith(("}image", "}script", "}foreignObject")) for node in image.iter()))
        labels = " ".join(" ".join(node.itertext()) for node in image.iter() if node.tag.endswith("}text"))
        for text in ("WireGuard inspection", "WireGuard delivery", "10.203.0.4", "10.204.0.4", "NO VPN"):
            self.assertIn(text, labels)

    def test_ubuntu_overlay_nic_ownership_is_explicit_and_separate_from_packet_flow(self):
        source = ROOT / "archive/prototypes/ew21-ubuntu-overlay.drawio"
        cells = {cell.get("id"): cell for cell in render_diagrams.validate_source(source)}
        for identifier, owner, subnet, address in (
            ("p-wan-nic", "vm-overlay-p", "router-p-card", "10.202.10.4"),
            ("p-pre-nic", "vm-overlay-p", "pre-p", "10.202.20.4"),
            ("p-post-nic", "vm-overlay-p", "post-p", "10.202.30.4"),
            ("fw-pre-nic", "vm-overlay-fw", "pre-p", "10.202.20.5"),
            ("fw-post-nic", "vm-overlay-fw", "post-p", "10.202.30.5"),
        ):
            with self.subTest(nic=identifier):
                self.assertIn(owner, cells[identifier].get("value"))
                self.assertIn(address, cells[identifier].get("value"))
                self.assertEqual(cells[identifier].get("parent"), subnet)
        self.assertEqual(cells["router-p-card"].get("parent"), "wan-p")
        self.assertEqual(cells["fw"].get("parent"), "fw-card")
        self.assertIn("vm-overlay-p | Router | 3 Azure NICs", cells["router-p-card"].get("value"))
        self.assertIn("vm-overlay-fw | Plain firewall | 2 Azure NICs", cells["fw-card"].get("value"))
        for identifier, owner, nic in (
            ("p-pre-owner", "router-p-card", "p-pre-nic"),
            ("p-post-owner", "router-p-card", "p-post-nic"),
            ("fw-pre-owner", "fw-card", "fw-pre-nic"),
            ("fw-post-owner", "fw-card", "fw-post-nic"),
        ):
            self.assertEqual((cells[identifier].get("source"), cells[identifier].get("target")), (owner, nic))
            self.assertIn("endArrow=none;", cells[identifier].get("style"))
            self.assertIn("dashed=1;", cells[identifier].get("style"))
            self.assertIn("strokeColor=#64748b;", cells[identifier].get("style"))
        for identifier, endpoints in (
            ("to-firewall", ("p-pre-nic", "fw-pre-nic")),
            ("fw-egress", ("fw-pre-nic", "fw-post-nic")),
            ("post-udr", ("fw-post-nic", "p-post-nic")),
        ):
            self.assertEqual((cells[identifier].get("source"), cells[identifier].get("target")), endpoints)
        image = ET.parse(source.with_suffix(".svg")).getroot()
        labels = " ".join(" ".join(node.itertext()) for node in image.iter() if node.tag.endswith("}text"))
        for cell_id in ("p-wan-nic", "p-pre-nic", "p-post-nic", "fw-pre-nic", "fw-post-nic",
                        "router-p-card", "fw-card", "fw-nic-summary", "legend"):
            for line in cells[cell_id].get("value").splitlines():
                self.assertIn(line, labels, "NIC ownership must remain readable in the rendered topology")

    def test_lab_topology_vm_icons_and_labels_are_large_enough(self):
        for path in ("architecture/ew18-managed-vpn-inspection.drawio",
                     "archive/prototypes/ew21-ubuntu-overlay.drawio"):
            for cell in render_diagrams.validate_source(ROOT / path):
                if cell.get("vertex") != "1" or "image=" not in cell.get("style", ""):
                    continue
                geometry = cell.find("mxGeometry")
                style = dict(p.split("=", 1) for p in cell.get("style").split(";") if "=" in p)
                if style["image"] == "img/lib/azure2/networking/Network_Interfaces.svg":
                    self.assertGreaterEqual(float(style["imageWidth"]), 32)
                    self.assertGreaterEqual(float(style["imageHeight"]), 32)
                    self.assertGreaterEqual(float(geometry.get("width")), 250)
                    self.assertGreaterEqual(float(geometry.get("height")), 40)
                else:
                    self.assertGreaterEqual(float(geometry.get("width")), 80)
                    self.assertGreaterEqual(float(geometry.get("height")), 80)
                self.assertGreaterEqual(float(style["fontSize"]), 18)

    def test_overlay_independence_diagram_marks_removed_resources_and_limits(self):
        source = ROOT / "archive/prototypes/ew21-ubuntu-overlay.drawio"
        cells = {c.get("id"): c for c in render_diagrams.validate_source(source)}
        lifecycle = cells["customer-lifecycle"].get("value")
        for text in ("192.168.77.0/24", "REMOVED", "24 original-source", "6 selective",
                     "combined runs", "DHCP", "Not an uninterrupted"):
            self.assertIn(text, lifecycle)
        for text in ("RFC1918", "AllowedIPs 0.0.0.0/0", "No per-VNet"):
            self.assertIn(text, cells["p-notes"].get("value"))

    def test_rendered_diagrams_use_portable_svg_text_and_no_scripts(self):
        files = sorted((ROOT / "docs/diagrams").glob("*.svg"))
        self.assertEqual(len(files), 6)
        for path in files:
            diagram = ET.parse(path).getroot()
            self.assertEqual(diagram.tag, "{http://www.w3.org/2000/svg}svg")
            self.assertFalse(any(node.tag.endswith(("foreignObject", "script")) for node in diagram.iter()))
            self.assertFalse(any(node.tag.endswith("}image") for node in diagram.iter()))
            self.assertFalse(any(
                "data:" in value or (key.endswith("href") and not value.startswith("#"))
                for node in diagram.iter() for key, value in node.attrib.items()
            ))
            labels = " ".join(" ".join(
                " ".join(node.itertext()) for node in diagram.iter() if node.tag.endswith("}text")
            ).split())
            for tenant in ("tenant A", "tenant B", "tenant C", "tenant D"):
                self.assertIn(tenant, labels)

    def test_diagrams_are_legible_in_a_height_limited_browser_preview(self):
        for path in sorted((ROOT / "docs/diagrams").glob("*.svg")):
            diagram = ET.parse(path).getroot()
            width = float(diagram.get("width").removesuffix("px"))
            height = float(diagram.get("height").removesuffix("px"))
            self.assertGreaterEqual(width, 1700, path.name)
            self.assertLessEqual(height, 760, path.name)
            self.assertGreaterEqual(width / height, 2.2, path.name)
            scale = min(1420 / width, 420 / height, 1)
            essential = []
            for text in diagram.iter("{http://www.w3.org/2000/svg}text"):
                label = " ".join(" ".join(text.itertext()).split())
                if label in {"VNet 1", "VNet 2", "Check Point firewall", "vHub + native CloudGuard"} or (
                    label.startswith("Customer ") and "tenant" in label
                ) or "Provider tenant A" in label:
                    size = float(text.get("font-size").removesuffix("px"))
                    self.assertGreaterEqual(size * scale, 14, (path.name, label))
                    essential.append(label)
            self.assertGreaterEqual(len(essential), 5 if path.name.startswith("06-") else 12, path.name)

    def test_all_diagram_labels_survive_export_without_truncation(self):
        for path in sorted((ROOT / "docs/diagrams").glob("*.drawio")):
            cells = render_diagrams.validate_source(path)
            expected = {" ".join(cell.get("value").split()) for cell in cells if cell.get("value")}
            image = ET.parse(path.with_suffix(".svg")).getroot()
            visible = {
                " ".join(" ".join(text.itertext()).split())
                for text in image.iter("{http://www.w3.org/2000/svg}text")
            }
            self.assertTrue(expected.issubset(visible), (path.name, sorted(expected - visible)))

    def test_drawio_sources_preserve_tenant_ownership_and_correct_attachment_type(self):
        sources = sorted((ROOT / "docs/diagrams").glob("*.drawio"))
        self.assertEqual(len(sources), 6)
        for path in sources:
            if path.name.startswith("06-"):
                continue
            cells = {cell.get("id"): cell for cell in render_diagrams.validate_source(path)}
            native = path.name.startswith(("03-", "04-"))
            self.assertIn("tenant A", cells["provider-label"].get("value"))
            for customer in "bcd":
                tenant = "tenant-" + customer
                environment = "env-" + customer
                self.assertIn("tenant " + customer.upper(), cells[tenant + "-title"].get("value"))
                self.assertEqual(cells[environment].get("parent"), "tenant-a")
                self.assertEqual(cells["fw-" + customer].get("parent"), environment)
                if native or path.name.startswith("05-"):
                    self.assertEqual(cells["hub-" + customer].get("parent"), environment)
                else:
                    self.assertNotIn("hub-" + customer, cells)
                for number in (1, 2):
                    cloud = f"{customer}-vnet-{number}"
                    self.assertEqual(cells[cloud].get("parent"), tenant)
                    attachment = cells[f"attachment-{customer}-{number}"]
                    self.assertEqual(attachment.get("source"), cloud)
                    self.assertEqual(attachment.get("target"), ("hub-" if native else "fw-") + customer)
                if native:
                    insertion = cells["native-insertion-" + customer]
                    self.assertEqual(insertion.get("source"), "hub-" + customer)
                    self.assertEqual(insertion.get("target"), "fw-" + customer)
            self.assertEqual(
                "management-icon" in cells,
                path.stem in {"02-direct-peering-avnm", "04-vwan-avnm-preview"},
            )

    def test_ipsec_option_places_the_hub_in_customer_b_and_firewall_in_provider_a(self):
        path = ROOT / "docs/diagrams/06-customer-vwan-ipsec.drawio"
        cells = {cell.get("id"): cell for cell in render_diagrams.validate_source(path)}
        self.assertEqual(cells["hub-b"].get("parent"), "tenant-b")
        self.assertEqual(cells["fw-b"].get("parent"), "tenant-a")
        for number in (1, 2):
            self.assertEqual(cells[f"b-vnet-{number}"].get("parent"), "tenant-b")
        for name, endpoints in (
            ("ipsec-to-provider", ("hub-b", "fw-b")),
            ("ipsec-to-customer", ("fw-b", "hub-b")),
        ):
            self.assertEqual((cells[name].get("source"), cells[name].get("target")), endpoints)
        self.assertIn("EXPERIMENT", cells["status"].get("value"))
        self.assertIn("not validated", cells["status"].get("value"))
        for customer in ("c", "d"):
            self.assertIn("Repeat", cells[f"tenant-{customer}-repeat"].get("value"))

    def test_drawio_child_vertices_stay_inside_their_own_container(self):
        for path in sorted((ROOT / "docs/diagrams").glob("*.drawio")):
            cells = {cell.get("id"): cell for cell in render_diagrams.validate_source(path)}
            for name, cell in cells.items():
                if cell.get("vertex") != "1" or cell.get("parent") == "1":
                    continue
                geometry = cell.find("mxGeometry")
                parent = cells[cell.get("parent")].find("mxGeometry")
                for position, dimension in (("x", "width"), ("y", "height")):
                    start = float(geometry.get(position, "0"))
                    self.assertGreaterEqual(start, 0, (path.name, name))
                    self.assertLessEqual(
                        start + float(geometry.get(dimension)), float(parent.get(dimension)), (path.name, name),
                    )

    def test_portable_svg_keeps_text_and_icon_vectors_without_encoded_payloads(self):
        icon = (
            '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18">'
            '<defs><linearGradient id="gradient"><stop offset="0" stop-color="blue"/></linearGradient></defs>'
            '<path fill="url(#gradient)" d="M0 0 L18 18"/></svg>'
        )
        encoded = base64.b64encode(icon.encode()).decode()
        document = ET.Element("{" + render_diagrams.SVG + "}svg")
        ET.SubElement(document, "{" + render_diagrams.SVG + "}image", {
            "href": "data:image/svg+xml;" + "base64," + encoded,
            "x": "20", "y": "30", "width": "80", "height": "80",
        })
        switch = ET.SubElement(document, "{" + render_diagrams.SVG + "}switch")
        ET.SubElement(switch, "{" + render_diagrams.SVG + "}foreignObject")
        ET.SubElement(switch, "{" + render_diagrams.SVG + "}text").text = "Customer tenant B"
        rendered = render_diagrams.portable_svg(ET.tostring(document))
        root = ET.fromstring(rendered)
        inline = root.find("{" + render_diagrams.SVG + "}svg")
        self.assertEqual(inline.get("viewBox"), "0 0 18 18")
        self.assertEqual((inline.get("x"), inline.get("y")), ("20", "30"))
        self.assertIn(b"Customer tenant B", rendered)
        self.assertNotIn(b"base64", rendered)
        self.assertNotIn(b"foreignObject", rendered)
        self.assertIn(b"url(#icon-0-shape-0)", rendered)

    def test_portable_svg_rejects_non_vector_or_unresolved_icon_payloads(self):
        for href in ("https://example.com/image.svg", "data:image/png;" + "base64,AAAA"):
            root = ET.Element("{" + render_diagrams.SVG + "}svg")
            ET.SubElement(root, "{" + render_diagrams.SVG + "}image", href=href)
            with self.subTest(href=href), self.assertRaises(ValueError):
                render_diagrams.portable_svg(ET.tostring(root))
        for content in ('<script>alert(1)</script>', '<path onclick="run()" d="M0 0"/>'):
            raw = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 18 18">' + content + "</svg>"
            image = ET.Element("{" + render_diagrams.SVG + "}image", href=(
                "data:image/svg+xml;" + "base64," + base64.b64encode(raw.encode()).decode()
            ))
            with self.subTest(content=content), self.assertRaises(ValueError):
                render_diagrams.inline_icon(image, 0)


class LocalConfigurationTests(unittest.TestCase):
    def test_missing_profile_fails_before_token_command(self):
        with tempfile.TemporaryDirectory() as temporary:
            with patch.dict(os.environ, {"FAAS_ACCOUNT_PROFILE": str(Path(temporary) / "missing.json")}):
                with patch("lab.subprocess.run") as command:
                    with self.assertRaisesRegex(RuntimeError, "Missing local account profile"):
                        Arm(Path(temporary)).token("A")
                command.assert_not_called()

    def test_profiles_require_explicit_distinct_canonical_scopes(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "accounts.json"
            profiles = synthetic_accounts()
            path.write_text(json.dumps(profiles))
            with patch.dict(os.environ, {"FAAS_ACCOUNT_PROFILE": str(path)}):
                self.assertEqual(dict(AccountProfiles()), profiles)
                profiles["B"]["tenant"] = profiles["A"]["tenant"]
                path.write_text(json.dumps(profiles))
                with self.assertRaises(ValueError):
                    dict(AccountProfiles())
                path.write_text(json.dumps({"A": {"tenant": "<placeholder>", "subscription": "<placeholder>"}, "B": {}}))
                with self.assertRaises(ValueError):
                    dict(AccountProfiles())

    def test_setup_never_overwrites_existing_local_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "accounts.example.json").write_text((ROOT / "accounts.example.json").read_text())
            for package in ("avnm-faas-lab", "cloudguard-vwan-lab"):
                (root / package).mkdir()
                for name in ("config.example.json", "plan.example.json"):
                    (root / package / name).write_text((ROOT / package / name).read_text())
            with patch.object(setup_local, "ROOT", root), patch("sys.argv", ["setup_local.py"]):
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(setup_local.main(), 0)
                    config = root / "avnm-faas-lab/config.json"
                    config.write_text('{"privateLocalSentinel": true}\n')
                    before = config.read_bytes()
                    self.assertEqual(setup_local.main(), 0)
            self.assertEqual(config.read_bytes(), before)
            self.assertEqual(stat.S_IMODE((root / ".local/accounts.json").stat().st_mode), 0o600)
            for package in ("avnm-faas-lab", "cloudguard-vwan-lab"):
                plan = json.loads((root / package / ".azure/infrastructure-plan.json").read_text())
                self.assertFalse(plan["meta"]["executionApproved"])

    def test_extracted_guest_helpers_keep_result_contract(self):
        payload = {"value": [{"message": 'FAAS_RESULT_BEGIN\n[{"ok":true}]\nFAAS_RESULT_END\nREADY'}]}
        self.assertEqual(extract_guest_result(payload), [{"ok": True}])
        require_marker(payload, "READY")
        with self.assertRaises(RuntimeError):
            extract_guest_result({"value": []})
        lines = request_script([{"test": "fixture", "host": "192.0.2.1", "port": 8080, "path": "/"}])
        compile(lines[1], "<guest-probe>", "exec")


if __name__ == "__main__":
    unittest.main()
