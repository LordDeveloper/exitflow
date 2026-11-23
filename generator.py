import urllib.request
import ipaddress
import json
from pathlib import Path
import ssl

URL = "https://api.mullvad.net/www/relays/wireguard/"
LOCAL_JSON = "relays.json"

OUTPUT_ROUTES_FILE = "mullvad-offline.rsc"
OUTPUT_RESET_FILE = "reset-settings.rsc"

PROXY = ""

INTERFACE_NAME = "exit"

def get_relays_data():
    storage = Path(__file__).resolve().parent / "storage"
    for source in (Path(LOCAL_JSON), Path("relay.json"), storage / LOCAL_JSON, storage / "relay.json"):
        if not source.is_file():
            continue
        print(f"Reading relays from local file '{source}'...")
        with source.open(encoding="utf-8-sig") as f:
            return json.load(f)

    print(f"Downloading Mullvad WireGuard relays from {URL}...")
    ctx = ssl.create_default_context()
    proxy_handler = urllib.request.ProxyHandler({"http": PROXY, "https": PROXY} if PROXY else {})
    opener = urllib.request.build_opener(proxy_handler, urllib.request.HTTPSHandler(context=ctx))
    opener.addheaders = [("User-Agent", "Mozilla/5.0")]
    with opener.open(URL, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))

def build_route_lines(relays, keep_installed_endpoints=True):
    endpoints = sorted({
        ipaddress.IPv4Address(relay["ipv4_addr_in"])
        for relay in relays
        if relay.get("ipv4_addr_in")
    })
    if not endpoints:
        raise ValueError("No Mullvad IPv4 endpoints selected")

    lines = [
        "# RouterOS v7 - install direct endpoint routes before removing legacy policy",
        "{",
        f'    :local uplink "{INTERFACE_NAME}"',
        '    :local routeTag "Mullvad endpoint via exit"',
        '    :if ([:len [/interface wireguard find where name=$uplink and running=yes and disabled=no]] != 1) do={ :error "exit must be running" }',
        '    :local prefixes {' + ';'.join(f'"{ip}/32"' for ip in endpoints) + '}',
    ]
    if keep_installed_endpoints:
        lines.extend([
            '    :foreach peer in=[/interface wireguard peers find where interface~"^mv-wg-" and disabled=no] do={',
            '        :local ip [:toip [/interface wireguard peers get $peer endpoint-address]]',
            '        :if ([:typeof $ip] != "ip") do={ :set ip [:toip [/interface wireguard peers get $peer current-endpoint-address]] }',
            '        :if ([:typeof $ip] != "ip") do={ :error "An enabled Mullvad peer has no usable IPv4 endpoint" }',
            '        :local prefix ([:tostr $ip] . "/32")',
            '        :if ([:typeof [:find $prefixes $prefix]] = "nil") do={ :set prefixes ($prefixes, $prefix) }',
            '    }',
        ])
    lines.extend([
        '    :foreach peer in=[/interface wireguard peers find where interface=$uplink and disabled=no] do={',
        '        :foreach field in={"endpoint-address";"current-endpoint-address"} do={',
        '            :local ip [:toip [/interface wireguard peers get $peer $field]]',
        '            :if ([:typeof $ip] = "ip") do={',
        '                :if ([:typeof [:find $prefixes ([:tostr $ip] . "/32")]] != "nil") do={ :error "A Mullvad endpoint overlaps the exit endpoint" }',
        '            }',
        '        }',
        '    }',
        '    :foreach prefix in=$prefixes do={',
        '        :if ([:len [/ip route find where routing-table=main and dst-address=$prefix and disabled=no and gateway!=$uplink]] > 0) do={ :error ("Conflicting main route for " . $prefix) }',
        '    }',
        '    :if ([:len [/ip firewall nat find where chain=srcnat and action=masquerade and out-interface=$uplink and disabled=no]] = 0) do={',
        '        /ip firewall nat add chain=srcnat action=masquerade out-interface=$uplink comment="NAT for WireGuard exit"',
        '    }',
        '    :foreach prefix in=$prefixes do={',
        '        :if ([:len [/ip route find where routing-table=main and dst-address=$prefix and gateway=$uplink and disabled=no]] = 0) do={',
        '            /ip route add dst-address=$prefix gateway=$uplink routing-table=main comment=$routeTag',
        '        }',
        '    }',
        '    :foreach prefix in=$prefixes do={',
        '        :if ([:len [/ip route find where routing-table=main and dst-address=$prefix and gateway=$uplink and active=yes]] = 0) do={ :error ("Inactive route for " . $prefix . ". Retry after routes converge.") }',
        '    }',
        '    /ip firewall mangle remove [find where dynamic=no and action=mark-routing and dst-address-list="MVIPs" and new-routing-mark="mv2tr"]',
        '    /ip firewall filter remove [find where dynamic=no and chain=forward and action=accept and dst-address-list="MVIPs" and comment="Bypass FastTrack for MVIPs"]',
        '    /routing rule remove [find where table="mv2tr" and routing-mark="mv2tr" and action=lookup-only-in-table]',
        '    /routing rule remove [find where table="mv2tr" and action=lookup-only-in-table and comment="MVIP handshake via mv2tr"]',
        '    /ip route remove [find where dynamic=no and routing-table="mv2tr" and gateway=$uplink and (comment="Mullvad Route via toTR" or comment="default via toTR" or comment="MVIP via toTR" or comment="default via exit" or comment="MVIP via exit")]',
        '    :if (([:len [/ip firewall mangle find where dst-address-list="MVIPs" or src-address-list="MVIPs"]] = 0) and ([:len [/ip firewall filter find where dst-address-list="MVIPs" or src-address-list="MVIPs"]] = 0) and ([:len [/ip firewall nat find where dst-address-list="MVIPs" or src-address-list="MVIPs"]] = 0) and ([:len [/ip firewall raw find where dst-address-list="MVIPs" or src-address-list="MVIPs"]] = 0)) do={',
        '        /ip firewall address-list remove [find where list="MVIPs" and dynamic=no]',
        '    }',
        '    :foreach route in=[/ip route find where routing-table=main and gateway=$uplink and dynamic=no and (comment=$routeTag or comment="Mullvad endpoint via toTR")] do={',
        '        :local prefix [:tostr [/ip route get $route dst-address]]',
        '        :if ([:typeof [:find $prefixes $prefix]] = "nil") do={ /ip route remove $route }',
        '    }',
        '    :put ("Verified Mullvad endpoint routes in main: " . [:len $prefixes])',
        "}",
    ])
    return lines, len(endpoints)


def generate_routes_rsc(relays):
    lines, endpoint_count = build_route_lines(relays)
    Path(OUTPUT_ROUTES_FILE).write_text("\n".join(lines) + "\n", encoding="utf-8")
    return endpoint_count


def generate_reset_rsc(catalog):
    routes, endpoint_count = build_route_lines(catalog, keep_installed_endpoints=False)
    cleanup = [
        '    /ip firewall mangle remove [find where dynamic=no and (new-routing-mark~"^mv-wg-" or new-routing-mark="mv2tr")]',
        '    /ip firewall filter remove [find where dynamic=no and (src-address-list~"^mv-wg-" or dst-address-list~"^mv-wg-")]',
        '    /ip firewall nat remove [find where dynamic=no and out-interface~"^mv-wg-"]',
        '    /routing rule remove [find where table~"^mv-wg-" or routing-mark~"^mv-wg-" or table="mv2tr" or routing-mark="mv2tr"]',
        '    /ip route remove [find where dynamic=no and (routing-table~"^mv-wg-" or routing-table="mv2tr")]',
        '    /ip address remove [find where dynamic=no and interface~"^mv-wg-"]',
        '    /interface wireguard peers remove [find where interface~"^mv-wg-"]',
        '    /interface wireguard remove [find where name~"^mv-wg-"]',
        '    /routing table remove [find where name~"^mv-wg-" or name="mv2tr"]',
        '    /ip firewall address-list remove [find where dynamic=no and list~"^mv-wg-"]',
        '    :put "Mullvad peer configuration cleared. Install peers from the Exitflow dashboard."',
    ]
    lines = ["# Exitflow reset: clear Mullvad peers and keep only endpoint routes via exit", *routes[:-1], *cleanup, "}"]
    Path(OUTPUT_RESET_FILE).write_text("\n".join(lines) + "\n", encoding="utf-8")
    return endpoint_count


def main():
    catalog = get_relays_data()
    endpoint_count = generate_routes_rsc(catalog)
    print(f"Generated '{OUTPUT_ROUTES_FILE}' ({endpoint_count} endpoint IPv4 routes).")
    generate_reset_rsc(catalog)
    print(f"Generated '{OUTPUT_RESET_FILE}' to clear Mullvad peers and rebuild endpoint routes.")


if __name__ == "__main__":
    main()
