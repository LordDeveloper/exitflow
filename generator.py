import urllib.request
import ipaddress
import json
import os
from pathlib import Path
import ssl

URL = "https://api.mullvad.net/www/relays/wireguard/"
LOCAL_JSON = "relays.json"

OUTPUT_ROUTES_FILE = "mullvad-offline.rsc"
OUTPUT_IFACES_FILE = "mullvad-interfaces.rsc"
OUTPUT_SIMPLE_FILE = "simple.rsc"
OUTPUT_RESET_FILE = "reset-settings.rsc"

PROXY = ""

INTERFACE_NAME = "toTR"

# ==========================================================
# اطلاعات اکانت Mullvad خود را اینجا وارد کنید (از فایل کانفیگ WireGuard مولواد بردارید)
# ==========================================================
WG_ENDPOINT_PORT = 51820

# اختیاری: کد کشورها برای محدود کردن لیست (مثلا: ["de", "se", "nl"]) - خالی باشد یعنی همه سرورها
FILTER_COUNTRIES = []

def load_wireguard_settings():
    names = ("MULLVAD_WG_PRIVATE_KEY", "WG_CLIENT_IPV4")
    env_file = Path(__file__).resolve().with_name(".env")
    values = {}
    if env_file.is_file():
        for line in env_file.read_text(encoding="utf-8-sig").splitlines():
            name, separator, value = line.partition("=")
            name = name.strip()
            if not separator or name not in names:
                continue
            value = value.strip()
            if len(value) >= 2 and value[0] in ("'", '"') and value[-1] == value[0]:
                value = value[1:-1]
            values[name] = value
    private_key, client_ipv4 = (os.environ.get(name, values.get(name, "")).strip() for name in names)
    return private_key, client_ipv4


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
        '    :local routeTag "Mullvad endpoint via toTR"',
        '    :if ([:len [/interface wireguard find where name=$uplink and running=yes and disabled=no]] != 1) do={ :error "toTR must be running" }',
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
        '                :if ([:typeof [:find $prefixes ([:tostr $ip] . "/32")]] != "nil") do={ :error "A Mullvad endpoint overlaps the toTR endpoint" }',
        '            }',
        '        }',
        '    }',
        '    :foreach prefix in=$prefixes do={',
        '        :if ([:len [/ip route find where routing-table=main and dst-address=$prefix and disabled=no and gateway!=$uplink]] > 0) do={ :error ("Conflicting main route for " . $prefix) }',
        '    }',
        '    :if ([:len [/ip firewall nat find where chain=srcnat and action=masquerade and out-interface=$uplink and disabled=no]] = 0) do={',
        '        /ip firewall nat add chain=srcnat action=masquerade out-interface=$uplink comment="NAT for WireGuard toTR"',
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
        '    /ip route remove [find where dynamic=no and routing-table="mv2tr" and gateway=$uplink and (comment="Mullvad Route via toTR" or comment="default via toTR" or comment="MVIP via toTR")]',
        '    :if (([:len [/ip firewall mangle find where dst-address-list="MVIPs" or src-address-list="MVIPs"]] = 0) and ([:len [/ip firewall filter find where dst-address-list="MVIPs" or src-address-list="MVIPs"]] = 0) and ([:len [/ip firewall nat find where dst-address-list="MVIPs" or src-address-list="MVIPs"]] = 0) and ([:len [/ip firewall raw find where dst-address-list="MVIPs" or src-address-list="MVIPs"]] = 0)) do={',
        '        /ip firewall address-list remove [find where list="MVIPs" and dynamic=no]',
        '    }',
        '    :foreach route in=[/ip route find where routing-table=main and gateway=$uplink and dynamic=no and comment=$routeTag] do={',
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


def build_interface_lines(relays, private_key, client_ipv4):
    lines = [
        "# Mullvad WireGuard peer provisioning (RouterOS v7)",
        f"# Replaces existing mv-wg-* interfaces with {len(relays)} peer(s).",
        f":local privKey \"{private_key}\"",
        f":local clientIp \"{client_ipv4}\"",
        "",
        "# 1. پاک‌سازی کامل تمام اینترفیس‌ها، روت‌ها و قوانین قبلی مربوط به mv-wg-",
        ":do { /ip firewall mangle remove [find where new-routing-mark~\"^mv-wg-\"] } on-error={}",
        ":do { /ip firewall filter remove [find where src-address-list~\"^mv-wg-\"] } on-error={}",
        ":do { /ip firewall nat remove [find where out-interface~\"^mv-wg-\"] } on-error={}",
        ":do { /routing rule remove [find where table~\"^mv-wg-\" or routing-mark~\"^mv-wg-\"] } on-error={}",
        ":do { /ip route remove [find where routing-table~\"^mv-wg-\" and dynamic=no] } on-error={}",
        ":do { /routing table remove [find where name~\"^mv-wg-\"] } on-error={}",
        ":do { /ip address remove [find where interface~\"^mv-wg-\"] } on-error={}",
        ":do { /interface wireguard peers remove [find where interface~\"^mv-wg-\"] } on-error={}",
        ":do { /interface wireguard remove [find where name~\"^mv-wg-\"] } on-error={}",
        "",
        "# 2. ساخت کامل زیرساخت برای تک‌تک Peer ها (Interface, Peer, IP, Table, Route, Mangle, Rule, Filter, NAT)",
    ]

    for r in relays:
        host = r["hostname"]
        iface = f"mv-wg-{host}"
        ip = r["ipv4_addr_in"]
        pubkey = r["pubkey"]
        comment = f"{r['country_name']} - {r['city_name']} ({host})"

        lines.extend([
            f"# --- {comment} ---",
            f"/interface wireguard add name=\"{iface}\" listen-port=0 mtu=1320 private-key=$privKey disabled=no comment=\"{comment}\"",
            f"/interface wireguard peers add interface=\"{iface}\" public-key=\"{pubkey}\" endpoint-address={ip} endpoint-port={WG_ENDPOINT_PORT} allowed-address=0.0.0.0/0 persistent-keepalive=25s disabled=no comment=\"{comment}\"",
            f"/ip address add address=$clientIp interface=\"{iface}\" disabled=no",
            f"/routing table add name=\"{iface}\" fib",
            f"/ip route add dst-address=0.0.0.0/0 gateway=\"{iface}\" routing-table=\"{iface}\" comment=\"{comment}\"",
            f"/ip firewall filter add chain=forward src-address-list=\"{iface}\" action=accept comment=\"Bypass FastTrack {iface}\"",
            f"/ip firewall mangle add chain=prerouting src-address-list=\"{iface}\" dst-address-type=!local action=mark-routing new-routing-mark=\"{iface}\" passthrough=no comment=\"Route Clients to {iface}\"",
            f"/routing rule add routing-mark=\"{iface}\" action=lookup-only-in-table table=\"{iface}\" comment=\"Strict {iface}\"",
            f"/ip firewall nat add chain=srcnat out-interface=\"{iface}\" action=masquerade comment=\"NAT {iface}\"",
            ""
        ])

    lines.append("# اطمینان از اینکه قوانین استثنای شبکه داخلی در بالاترین اولویت Routing Rule قرار دارند")
    lines.append(":do { /routing rule move [find where comment=\"Allow Private 10.x\"] destination=0 } on-error={}")
    lines.append(":do { /routing rule move [find where comment=\"Allow Local Networks\"] destination=0 } on-error={}")
    lines.append("")
    lines.append(f":put \"Full routing & firewall rules created for all {len(relays)} Mullvad peers!\"")

    return lines


def generate_interfaces_rsc(relays, output_file, private_key, client_ipv4):
    lines = build_interface_lines(relays, private_key, client_ipv4)
    Path(output_file).write_text("\n".join(lines) + "\n", encoding="utf-8")


def generate_reset_rsc(catalog, peer_relays, private_key, client_ipv4):
    routes, _ = build_route_lines(catalog, keep_installed_endpoints=False)
    interfaces = build_interface_lines(peer_relays, private_key, client_ipv4)
    # One RouterOS block stops before interface cleanup if route validation fails.
    lines = ["# Exitflow reset settings: rebuild Mullvad routes and peers", *routes[:-1]]
    lines.extend("    " + line if line else "" for line in interfaces)
    lines.extend([
        '    :foreach entry in=[/ip firewall address-list find where list~"^mv-wg-" and dynamic=no] do={',
        '        :local targetList [/ip firewall address-list get $entry list]',
        '        :if ([:len [/interface wireguard find where name=$targetList]] = 0) do={',
        '            /ip firewall address-list remove $entry',
        '        }',
        '    }',
        '    :put "Exitflow Mullvad settings rebuilt."',
        "}",
    ])
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    with open(OUTPUT_RESET_FILE, "w", encoding="utf-8", newline="\n",
              opener=lambda path, _: os.open(path, flags, 0o600)) as handle:
        handle.write("\n".join(lines) + "\n")


def select_relays(data):
    relays = []
    seen_locations = set()
    seen_ips = set()
    for relay in sorted(data, key=lambda row: row["hostname"]):
        if not relay.get("active", True) or not relay.get("ipv4_addr_in"):
            continue

        hostname_parts = relay["hostname"].lower().split("-")
        country = (relay.get("country_code") or hostname_parts[0]).lower()
        city = (relay.get("city_code") or hostname_parts[1]).lower()
        if FILTER_COUNTRIES and country not in FILTER_COUNTRIES:
            continue

        location = (country, city)
        ip = ipaddress.IPv4Address(relay["ipv4_addr_in"])
        if location in seen_locations or ip in seen_ips:
            continue
        seen_locations.add(location)
        seen_ips.add(ip)
        relays.append(relay)
    return relays


def main():
    private_key, client_ipv4 = load_wireguard_settings()
    catalog = get_relays_data()
    peer_relays = select_relays(catalog) if private_key else []
    if private_key and peer_relays:
        if not client_ipv4 or "/" not in client_ipv4:
            raise SystemExit("Set WG_CLIENT_IPV4 to the IPv4 address with prefix from your Mullvad config.")
        try:
            ipaddress.IPv4Interface(client_ipv4)
        except ValueError:
            raise SystemExit("WG_CLIENT_IPV4 must be a valid IPv4 address with prefix.") from None

    endpoint_count = generate_routes_rsc(catalog)
    print(f"Generated '{OUTPUT_ROUTES_FILE}' ({endpoint_count} endpoint IPv4 routes).")
    if peer_relays:
        generate_interfaces_rsc(peer_relays, OUTPUT_IFACES_FILE, private_key, client_ipv4)
        generate_interfaces_rsc(peer_relays[:1], OUTPUT_SIMPLE_FILE, private_key, client_ipv4)
        print(f"Generated '{OUTPUT_IFACES_FILE}' for {len(peer_relays)} peers.")
        print(f"Generated '{OUTPUT_SIMPLE_FILE}' for testing {peer_relays[0]['hostname']}.")
        generate_reset_rsc(catalog, peer_relays, private_key, client_ipv4)
        print(f"Generated '{OUTPUT_RESET_FILE}' to rebuild Mullvad settings.")
    elif private_key:
        print("No active peer relays matched the selection.")

if __name__ == "__main__":
    main()
