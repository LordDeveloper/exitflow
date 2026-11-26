import base64
import binascii
from contextlib import closing
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import random
import re
import sqlite3
import time
import urllib.request

from generator import URL

class CatalogFetchError(Exception):
    pass


DB_PATH = Path(__file__).resolve().parents[1] / "storage" / "database" / "exitflow.sqlite"
CATALOG_PATH = DB_PATH.parents[1] / "relays.json"
PEERS_PER_CREDENTIAL = 25


def connect_database():
    return sqlite3.connect(DB_PATH, timeout=10)


def initialize_database():
    DB_PATH.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.close(os.open(DB_PATH, os.O_CREAT | os.O_WRONLY, 0o600))
    with closing(connect_database()) as connection:
        with connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("CREATE TABLE IF NOT EXISTS settings (name TEXT PRIMARY KEY, value TEXT NOT NULL)")
            connection.execute("CREATE TABLE IF NOT EXISTS migrations (filename TEXT PRIMARY KEY, digest TEXT NOT NULL)")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS credentials (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    private_key TEXT NOT NULL UNIQUE,
                    address TEXT NOT NULL UNIQUE,
                    dns TEXT NOT NULL DEFAULT '',
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                )
                """
            )
            applied = {name for (name,) in connection.execute("SELECT filename FROM migrations")}
            legacy_path = None
            raw = None
            for filename in ("exitflow.json", "exitnode.json", "db.json"):
                if filename != "exitflow.json" and applied and filename not in applied:
                    continue
                candidate = DB_PATH.with_name(filename)
                try:
                    candidate_raw = candidate.read_bytes()
                except FileNotFoundError:
                    continue
                digest = hashlib.sha256(candidate_raw).hexdigest()
                migrated = connection.execute(
                    "SELECT digest FROM migrations WHERE filename = ?", (filename,)
                ).fetchone()
                if migrated != (digest,):
                    try:
                        data = json.loads(candidate_raw)
                    except ValueError as error:
                        raise ValueError(f"{filename} is not valid JSON") from error
                    if not isinstance(data, dict):
                        raise ValueError(f"{filename} must contain a JSON object")
                    existing = read_database(connection)
                    if any(key in existing and existing[key] != value for key, value in data.items()):
                        raise ValueError(f"{filename} conflicts with settings already stored in SQLite")
                    write_database(connection, data)
                    connection.execute(
                        "INSERT OR REPLACE INTO migrations (filename, digest) VALUES (?, ?)", (filename, digest)
                    )
                legacy_path = candidate
                raw = candidate_raw
                break
            migrate_legacy_wireguard(connection)
        if legacy_path is not None and raw is not None:
            try:
                if legacy_path.read_bytes() == raw:
                    legacy_path.unlink()
            except FileNotFoundError:
                pass


def migrate_legacy_wireguard(connection):
    row = connection.execute("SELECT value FROM settings WHERE name = ?", ("wireguard",)).fetchone()
    if not row:
        return
    try:
        settings = json.loads(row[0])
    except ValueError:
        return
    key = str(settings.get("key") or "").strip()
    address = str(settings.get("address") or "").strip()
    if not key or not address:
        return
    existing = connection.execute("SELECT COUNT(*) FROM credentials").fetchone()[0]
    if existing:
        return
    try:
        parsed = normalize_credential_fields("Legacy Mullvad", key, address, "")
    except ValueError:
        return
    now = time.time()
    connection.execute(
        "INSERT INTO credentials (name, private_key, address, dns, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
        (parsed["name"], parsed["private_key"], parsed["address"], parsed["dns"], now, now),
    )


def read_database(connection):
    return {name: json.loads(value) for name, value in connection.execute("SELECT name, value FROM settings")}


def write_database(connection, values):
    connection.executemany(
        "INSERT OR REPLACE INTO settings (name, value) VALUES (?, ?)",
        ((name, json.dumps(value, ensure_ascii=False)) for name, value in values.items()),
    )


def load_catalog():
    request = urllib.request.Request(URL, headers={"User-Agent": "Exitflow"})
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            return normalize_catalog(json.load(response))
    except (OSError, ValueError) as error:
        raise CatalogFetchError("دریافت فهرست از Mullvad ناموفق بود. از فایل JSON استفاده کنید یا دوباره تلاش کنید.") from error


def normalize_catalog(rows):
    if not isinstance(rows, list):
        raise ValueError("فایل فهرست باید آرایهٔ رله‌های WireGuard باشد.")
    catalog = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        name = row.get("hostname")
        if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9-]+", name):
            continue
        try:
            ip = str(ipaddress.IPv4Address(row["ipv4_addr_in"]))
            if len(base64.b64decode(row["pubkey"], validate=True)) != 32:
                continue
        except (KeyError, ValueError, TypeError):
            continue
        catalog[name] = {
            "name": name,
            "country": str(row.get("country_name", "")),
            "city": str(row.get("city_name", "")),
            "ip": ip,
            "publicKey": row["pubkey"],
            "active": row.get("active", True),
        }
    if not catalog:
        raise ValueError("هیچ رلهٔ IPv4 معتبری در فهرست پیدا نشد.")
    return [catalog[name] for name in sorted(catalog)]


def current_catalog(db):
    if "relay_catalog_override" in db:
        return db["relay_catalog_override"]
    try:
        return normalize_catalog(json.loads(CATALOG_PATH.read_text(encoding="utf-8-sig")))
    except FileNotFoundError:
        return db.get("relays", [])


def validate_private_key(key):
    try:
        if len(base64.b64decode(key, validate=True)) != 32:
            raise ValueError
    except (ValueError, binascii.Error, TypeError) as error:
        raise ValueError("کلید خصوصی WireGuard نامعتبر است.") from error
    return key.strip()


def validate_ipv4_address(address):
    try:
        if "/" not in address:
            raise ValueError
        parsed = ipaddress.IPv4Interface(address.strip())
    except (ValueError, TypeError) as error:
        raise ValueError("آدرس IPv4 تونل باید مثل 10.67.135.94/32 باشد.") from error
    return str(parsed)


def normalize_credential_fields(name, private_key, address, dns=""):
    label = str(name or "").strip() or "Mullvad"
    if len(label) > 80 or any(ord(char) < 32 for char in label):
        raise ValueError("نام کلید باید حداکثر ۸۰ نویسه و در یک خط باشد.")
    key = validate_private_key(str(private_key or "").strip())
    addr = validate_ipv4_address(str(address or "").strip())
    dns_value = str(dns or "").strip()
    if len(dns_value) > 120 or any(ord(char) < 32 for char in dns_value):
        raise ValueError("مقدار DNS نامعتبر است.")
    return {
        "name": label,
        "private_key": key,
        "address": addr,
        "dns": dns_value,
        "network": str(ipaddress.IPv4Interface(addr).network.network_address),
        "ipv4": str(ipaddress.IPv4Interface(addr).ip),
    }


def parse_wireguard_interface(raw, require_key=True, fallback_key=""):
    text = str(raw or "").replace("\r\n", "\n").replace("\r", "\n")
    if not text.strip():
        raise ValueError("متن کانفیگ خالی است.")
    section = "interface" if "[interface]" not in text.lower() else None
    values = {}
    device_name = ""
    for line in text.split("\n"):
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1].strip().lower()
            continue
        if section != "interface":
            continue
        if stripped.startswith("#"):
            match = re.search(r"Device:\s*(.+)$", stripped[1:].strip(), re.IGNORECASE)
            if match:
                device_name = match.group(1).strip()
            continue
        if "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        values[key.strip().lower()] = value.strip()
    private_key = (values.get("privatekey") or "").strip() or fallback_key
    address_raw = values.get("address", "")
    ipv4 = None
    for part in address_raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            ipv4 = str(ipaddress.IPv4Interface(part))
            break
        except ValueError:
            continue
    if require_key and not (values.get("privatekey") or "").strip():
        raise ValueError("از بخش [Interface] باید PrivateKey خوانده شود.")
    if not ipv4:
        raise ValueError("از بخش [Interface] باید Address IPv4 خوانده شود.")
    if not private_key:
        raise ValueError("کلید خصوصی برای این credential موجود نیست.")
    return normalize_credential_fields(device_name or "Mullvad", private_key, ipv4, values.get("dns", ""))


def credential_row(row, include_key=False):
    item = {
        "id": row["id"],
        "name": row["name"],
        "address": row["address"],
        "ipv4": str(ipaddress.IPv4Interface(row["address"]).ip),
        "network": str(ipaddress.IPv4Interface(row["address"]).network.network_address),
        "dns": row["dns"] or "",
        "hasKey": True,
        "createdAt": row["created_at"],
        "updatedAt": row["updated_at"],
        "peerLimit": PEERS_PER_CREDENTIAL,
    }
    if include_key:
        item["key"] = row["private_key"]
    return item


def list_credentials(connection, include_key=False):
    rows = connection.execute(
        "SELECT id, name, private_key, address, dns, created_at, updated_at FROM credentials ORDER BY name COLLATE NOCASE, id"
    ).fetchall()
    keys = ("id", "name", "private_key", "address", "dns", "created_at", "updated_at")
    return [credential_row(dict(zip(keys, row)), include_key=include_key) for row in rows]


def get_credential(connection, credential_id):
    row = connection.execute(
        "SELECT id, name, private_key, address, dns, created_at, updated_at FROM credentials WHERE id = ?",
        (credential_id,),
    ).fetchone()
    if not row:
        raise ValueError("این credential پیدا نشد.")
    keys = ("id", "name", "private_key", "address", "dns", "created_at", "updated_at")
    return dict(zip(keys, row))


def insert_credential(connection, fields):
    now = time.time()
    try:
        cursor = connection.execute(
            "INSERT INTO credentials (name, private_key, address, dns, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
            (fields["name"], fields["private_key"], fields["address"], fields["dns"], now, now),
        )
    except sqlite3.IntegrityError as error:
        same_key = connection.execute(
            "SELECT id, name FROM credentials WHERE private_key = ?", (fields["private_key"],)
        ).fetchone()
        same_address = connection.execute(
            "SELECT id, name FROM credentials WHERE address = ?", (fields["address"],)
        ).fetchone()
        if same_key:
            raise ValueError(f"این PrivateKey از قبل به‌عنوان «{same_key[1]}» ذخیره شده است.") from error
        if same_address:
            raise ValueError(f"این Address از قبل روی «{same_address[1]}» ثبت شده است.") from error
        raise ValueError("این کلید یا آدرس از قبل ذخیره شده است.") from error
    return get_credential(connection, cursor.lastrowid)


def update_credential(connection, credential_id, fields):
    get_credential(connection, credential_id)
    now = time.time()
    try:
        connection.execute(
            "UPDATE credentials SET name = ?, private_key = ?, address = ?, dns = ?, updated_at = ? WHERE id = ?",
            (fields["name"], fields["private_key"], fields["address"], fields["dns"], now, credential_id),
        )
    except sqlite3.IntegrityError as error:
        raise ValueError("این کلید یا آدرس از قبل ذخیره شده است.") from error
    return get_credential(connection, credential_id)


def delete_credential(connection, credential_id):
    deleted = connection.execute("DELETE FROM credentials WHERE id = ?", (credential_id,)).rowcount
    if not deleted:
        raise ValueError("این credential پیدا نشد.")
    return {"ok": True, "id": credential_id}


def pick_credential(connection, usage=None, credential_id=None):
    usage = usage if isinstance(usage, dict) else {}
    rows = list_credentials(connection, include_key=True)
    if not rows:
        raise ValueError("ابتدا حداقل یک credential Mullvad اضافه کنید.")
    if credential_id is not None:
        chosen = next((row for row in rows if row["id"] == credential_id), None)
        if chosen is None:
            raise ValueError("credential انتخاب‌شده پیدا نشد.")
        used = int(usage.get(str(chosen["id"]), usage.get(chosen["id"], 0)) or 0)
        if used >= PEERS_PER_CREDENTIAL:
            raise ValueError(f"این کلید به سقف {PEERS_PER_CREDENTIAL} peer رسیده است.")
        return chosen
    available = []
    for row in rows:
        used = int(usage.get(str(row["id"]), usage.get(row["id"], 0)) or 0)
        if used < PEERS_PER_CREDENTIAL:
            available.append(row)
    if not available:
        raise ValueError(f"همهٔ کلیدها به سقف {PEERS_PER_CREDENTIAL} peer رسیده‌اند. یک credential جدید اضافه کنید.")
    return random.choice(available)


def dispatch(path, method, payload):
    if path == "/dashboard/relays" and method == "POST":
        catalog = normalize_catalog(payload["relays"]) if "relays" in payload else load_catalog()
        with closing(connect_database()) as connection, connection:
            write_database(connection, {"relay_catalog_override": catalog})
        return catalog
    with closing(connect_database()) as connection, connection:
        if method == "POST":
            connection.execute("BEGIN IMMEDIATE")
        db = read_database(connection)
        if path == "/dashboard/client-names":
            names = db.get("client_names", {})
            if method == "GET":
                return names
            if method == "POST":
                identity = payload.get("identity", "")
                name = payload.get("name", "")
                if not isinstance(identity, str) or not isinstance(name, str):
                    raise ValueError("نام یا شناسهٔ دستگاه نامعتبر است.")
                if not re.fullmatch(r"mac:[0-9a-f]{12}", identity):
                    if not identity.startswith("ip:"):
                        raise ValueError("شناسهٔ دستگاه نامعتبر است.")
                    identity = "ip:" + str(ipaddress.IPv4Address(identity[3:]))
                name = name.strip()
                if len(name) > 80 or any(ord(char) < 32 for char in name):
                    raise ValueError("نام دستگاه باید حداکثر ۸۰ نویسه و در یک خط باشد.")
                if name:
                    names[identity] = name
                else:
                    names.pop(identity, None)
                write_database(connection, {"client_names": names})
                return {"identity": identity, "name": name}
        if path == "/dashboard/relays" and method == "GET":
            return current_catalog(db)
        if path == "/dashboard/credentials":
            if method == "GET":
                return {"credentials": list_credentials(connection), "peerLimit": PEERS_PER_CREDENTIAL}
            if method == "POST":
                action = str(payload.get("action") or "create").strip().lower()
                if action == "create":
                    if payload.get("raw"):
                        fields = parse_wireguard_interface(payload.get("raw"))
                        if payload.get("name"):
                            fields["name"] = str(payload.get("name")).strip() or fields["name"]
                    else:
                        fields = normalize_credential_fields(
                            payload.get("name"), payload.get("key"), payload.get("address"), payload.get("dns", "")
                        )
                    row = insert_credential(connection, fields)
                    return credential_row(row, include_key=False)
                if action == "update":
                    credential_id = int(payload.get("id"))
                    existing = get_credential(connection, credential_id)
                    if payload.get("raw"):
                        fields = parse_wireguard_interface(
                            payload.get("raw"),
                            require_key=False,
                            fallback_key=existing["private_key"],
                        )
                        if payload.get("name"):
                            fields["name"] = str(payload.get("name")).strip() or fields["name"]
                    else:
                        key = payload.get("key") or existing["private_key"]
                        fields = normalize_credential_fields(
                            payload.get("name", existing["name"]),
                            key,
                            payload.get("address", existing["address"]),
                            payload.get("dns", existing["dns"]),
                        )
                    row = update_credential(connection, credential_id, fields)
                    result = credential_row(row, include_key=payload.get("includeKey") is True)
                    if payload.get("includeKey") is True:
                        result["key"] = row["private_key"]
                    return result
                if action == "delete":
                    return delete_credential(connection, int(payload.get("id")))
                raise ValueError("عملیات credentials نامعتبر است.")
        if path == "/dashboard/wireguard":
            # Compatibility for older UI/scripts: expose first credential.
            rows = list_credentials(connection, include_key=True)
            first = rows[0] if rows else None
            if method == "GET":
                if not first:
                    return {"address": "", "hasKey": False}
                return {"address": first["address"], "hasKey": True, "credentialId": first["id"], "name": first["name"]}
            if method == "POST":
                fields = normalize_credential_fields(
                    payload.get("name") or (first["name"] if first else "Mullvad"),
                    payload.get("key") or (first["key"] if first else ""),
                    payload.get("address") or (first["address"] if first else ""),
                    payload.get("dns") or (first["dns"] if first else ""),
                )
                if first:
                    row = update_credential(connection, first["id"], fields)
                else:
                    row = insert_credential(connection, fields)
                result = credential_row(row, include_key=payload.get("includeKey") is True)
                if payload.get("includeKey") is True:
                    result["key"] = row["private_key"]
                return result
        if path == "/dashboard/provision" and method == "POST":
            usage = payload.get("usage") if isinstance(payload.get("usage"), dict) else {}
            credential_id = payload.get("credentialId")
            if credential_id is not None:
                credential_id = int(credential_id)
            chosen = pick_credential(connection, usage=usage, credential_id=credential_id)
            relay = next((row for row in current_catalog(db) if row["name"] == payload.get("name")), None)
            if relay is None:
                raise ValueError("Relay is missing from the local catalog.")
            return {
                "relay": relay,
                "address": chosen["address"],
                "key": chosen["key"],
                "network": chosen["network"],
                "credentialId": chosen["id"],
                "credentialName": chosen["name"],
                "peerLimit": PEERS_PER_CREDENTIAL,
            }
    raise LookupError
