import base64
import binascii
from contextlib import closing
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import urllib.request

from generator import URL

class CatalogFetchError(Exception):
    pass


DB_PATH = Path(__file__).resolve().parents[1] / "storage" / "database" / "exitflow.sqlite"
CATALOG_PATH = DB_PATH.parents[1] / "relays.json"


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
            applied = {name for (name,) in connection.execute("SELECT filename FROM migrations")}
            for filename in ("exitflow.json", "exitnode.json", "db.json"):
                if filename != "exitflow.json" and applied and filename not in applied:
                    continue
                legacy_path = DB_PATH.with_name(filename)
                try:
                    raw = legacy_path.read_bytes()
                except FileNotFoundError:
                    continue
                digest = hashlib.sha256(raw).hexdigest()
                migrated = connection.execute(
                    "SELECT digest FROM migrations WHERE filename = ?", (filename,)
                ).fetchone()
                if migrated != (digest,):
                    try:
                        data = json.loads(raw)
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
                break
            else:
                return
        # Remove only the version that was successfully committed.
        try:
            if legacy_path.read_bytes() == raw:
                legacy_path.unlink()
        except FileNotFoundError:
            pass


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
        settings = db.get("wireguard", {})
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
        if path == "/dashboard/wireguard":
            if method == "GET":
                return {"address": settings.get("address", ""), "hasKey": bool(settings.get("key"))}
            if method == "POST":
                address = payload.get("address", "").strip()
                key = payload.get("key", "").strip() or settings.get("key", "")
                try:
                    if len(base64.b64decode(key, validate=True)) != 32 or "/" not in address:
                        raise ValueError
                    parsed_address = ipaddress.IPv4Interface(address)
                    address = str(parsed_address)
                except (ValueError, binascii.Error):
                    raise ValueError("Enter a valid WireGuard private key and IPv4 address with prefix.") from None
                write_database(connection, {"wireguard": {"address": address, "key": key}})
                result = {"address": address, "hasKey": True}
                if payload.get("includeKey") is True:
                    result["key"] = key
                    result["network"] = str(parsed_address.network.network_address)
                return result
        if path == "/dashboard/provision" and method == "POST":
            if not settings.get("key"):
                raise ValueError("Save your WireGuard settings first.")
            relay = next((row for row in current_catalog(db) if row["name"] == payload.get("name")), None)
            if relay is None:
                raise ValueError("Relay is missing from the local catalog.")
            return {"relay": relay, "address": settings["address"], "key": settings["key"]}
    raise LookupError
