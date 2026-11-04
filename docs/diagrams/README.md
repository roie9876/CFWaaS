# Deployment diagrams

Options 1-5 put **customer workload VNets above** and **Check Point/provider
tenant A below**. Option 6 puts the **customer-owned vWAN on the left** and
the **provider firewall on the right**. Each customer has its own firewall
environment; no links between customer B, C and D are implied.

| Option | GitHub preview | Full-size original | Editable Draw.io source |
| --- | --- | --- | --- |
| 1. Direct peering without AVNM, own controller | [View](01-direct-peering-controller.svg) | [Open](https://github.com/roie9876/CFWaaS/raw/refs/heads/main/docs/diagrams/01-direct-peering-controller.svg) | [Edit](01-direct-peering-controller.drawio) |
| 2. Direct peering + AVNM | [View](02-direct-peering-avnm.svg) | [Open](https://github.com/roie9876/CFWaaS/raw/refs/heads/main/docs/diagrams/02-direct-peering-avnm.svg) | [Edit](02-direct-peering-avnm.drawio) |
| Native CloudGuard in vWAN | [View](03-vwan-cloudguard.svg) | [Open](https://github.com/roie9876/CFWaaS/raw/refs/heads/main/docs/diagrams/03-vwan-cloudguard.svg) | [Edit](03-vwan-cloudguard.drawio) |
| Native CloudGuard/vWAN + AVNM preview | [View](04-vwan-avnm-preview.svg) | [Open](https://github.com/roie9876/CFWaaS/raw/refs/heads/main/docs/diagrams/04-vwan-avnm-preview.svg) | [Edit](04-vwan-avnm-preview.drawio) |
| vWAN with indirect spokes | [View](05-vwan-indirect-spokes.svg) | [Open](https://github.com/roie9876/CFWaaS/raw/refs/heads/main/docs/diagrams/05-vwan-indirect-spokes.svg) | [Edit](05-vwan-indirect-spokes.drawio) |
| Customer vWAN + provider IPsec | [View](06-customer-vwan-ipsec.svg) | [Open](https://github.com/roie9876/CFWaaS/raw/refs/heads/main/docs/diagrams/06-customer-vwan-ipsec.svg) | [Edit](06-customer-vwan-ipsec.drawio) |

The images use a compact landscape layout and larger type/icons so they remain
readable in GitHub's height-limited preview. For browser zoom or downloading the
original vector image, use **Full-size original**, rather than the file preview.
Access still requires your existing private-repository permissions.

Open the `.drawio` file in Draw.io desktop or the VS Code Draw.io extension.
These are editable shapes, text, connectors and built-in Azure icons, not a
flattened screenshot. Use the local exporter documented in
[Contributing](../../CONTRIBUTING.md) after editing.

The presentation style uses blue for customer networking and pink for provider
inspection. Validation/preview labels remain explicit: the visuals are reference
architectures, not claims that every option is a deployed production service.

## Symbols and fidelity

- **Blue clouds:** conceptual customer workload VNets, not a particular Azure
  compute/Cloud Services product icon.
- **Pink bricks:** original generic firewall-role glyph, labeled Check Point;
  it is not an Azure Firewall icon or a Check Point trademark/logo.
- **Azure Virtual WAN Hub:** native Azure hub icon, shown only where a vHub
  actually participates in the architecture.
- **Azure Network Manager:** native Azure icon, used only for AVNM management;
  it is not a traffic hop or a symbol for the custom Check Point controller.
- **Solid blue lines:** network attachments. The traffic-path caption describes
  how inspection works; the lines are not a promise of a particular protocol.

Two VNets and one environment per customer are shown to keep each image simple.
Option 6 instead details customer B's vWAN-to-provider tunnel; C/D are labeled
as independent repetitions. Its managed hub belongs to the customer, not A.
The current lab's actual scope and each option's qualification status are
described in the deployment guides. An intended Check Point role does not mean
the successful Ubuntu simulator lab qualified CloudGuard or HA.

## Icon sources and usage

Azure icons are Microsoft product artwork, used without changing their shapes
to illustrate the Azure products they represent. See Microsoft's
[Azure icon usage guidelines](https://learn.microsoft.com/azure/architecture/icons/).
This does not imply Microsoft or Check Point endorsement.

The paths were verified against the Draw.io Azure2 catalog:

- `img/lib/azure2/networking/Virtual_WAN_Hub.svg`
- `img/lib/azure2/other/Azure_Network_Manager.svg`

The installed Draw.io desktop application resolves these built-in assets
locally. The rendered SVGs include their vector shapes so GitHub does not need
to load remote images. Sources can also be inspected in the public
[Draw.io Azure2 library](https://github.com/jgraph/drawio/tree/dev/src/main/webapp/img/lib/azure2).
Draw.io's [license](https://github.com/jgraph/drawio/blob/dev/LICENSE) does not
replace the icon owner's product-artwork usage terms.
