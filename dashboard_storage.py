import base64
import binascii
import ipaddress
import json
import os
from pathlib import Path
import re
import tempfile
import threading
import urllib.request

from generator import URL

DB_PATH = Path(__file__).resolve().parent / "storage" / "database" / "db.json"
LOCK = threading.Lock()


def read_database():
    try:
        return json.loads(DB_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}


def write_database(db):
    DB_PATH.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=DB_PATH.parent, delete=False) as file:
        try:
            json.dump(db, file, ensure_ascii=False)
            file.close()
            os.replace(file.name, DB_PATH)
        finally:
            Path(file.name).unlink(missing_ok=True)


def load_catalog():
    request = urllib.request.Request(URL, headers={"User-Agent": "Exitflow"})
    with urllib.request.urlopen(request, timeout=20) as response:
        rows = json.load(response)
    catalog = []
    for row in rows:
        if not re.fullmatch(r"[a-z0-9-]+", row["hostname"]):
            continue
        try:
            ip = str(ipaddress.IPv4Address(row["ipv4_addr_in"]))
            if len(base64.b64decode(row["pubkey"], validate=True)) != 32:
                continue
        except (ValueError, TypeError):
            continue
        catalog.append({
            "name": row["hostname"],
            "country": row["country_name"],
            "city": row["city_name"],
            "ip": ip,
            "publicKey": row["pubkey"],
            "active": row.get("active", True),
        })
    if not catalog:
        raise ValueError("Mullvad returned no IPv4 relays")
    return sorted(catalog, key=lambda row: row["name"])


def dispatch(path, method, payload):
    if path == "/dashboard/relays" and method == "POST":
        catalog = load_catalog()
        with LOCK:
            db = read_database()
            db["relays"] = catalog
            write_database(db)
        return catalog
    with LOCK:
        db = read_database()
        settings = db.get("wireguard", {})
        if path == "/dashboard/relays" and method == "GET":
            return db.get("relays", [])
        if path == "/dashboard/wireguard":
            if method == "GET":
                return {"address": settings.get("address", ""), "hasKey": bool(settings.get("key"))}
            if method == "POST":
                address = payload.get("address", "").strip()
                key = payload.get("key", "").strip() or settings.get("key", "")
                try:
                    if len(base64.b64decode(key, validate=True)) != 32 or "/" not in address:
                        raise ValueError
                    address = str(ipaddress.IPv4Interface(address))
                except (ValueError, binascii.Error):
                    raise ValueError("Enter a valid WireGuard private key and IPv4 address with prefix.") from None
                db["wireguard"] = {"address": address, "key": key}
                write_database(db)
                return {"address": address, "hasKey": True}
        if path == "/dashboard/provision" and method == "POST":
            if not settings.get("key"):
                raise ValueError("Save your WireGuard settings first.")
            relay = next((row for row in db.get("relays", []) if row["name"] == payload.get("name")), None)
            if relay is None:
                raise ValueError("Relay is missing from the local catalog.")
            return {"relay": relay, "address": settings["address"], "key": settings["key"]}
    raise LookupError
