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

class CatalogFetchError(Exception):
    pass


DB_PATH = Path(__file__).resolve().parents[1] / "storage" / "database" / "exitflow.json"
CATALOG_PATH = DB_PATH.parents[1] / "relays.json"
LOCK = threading.Lock()


def read_database():
    try:
        return json.loads(DB_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError:
        for legacy_name in ("exitnode.json", "db.json"):
            try:
                DB_PATH.with_name(legacy_name).rename(DB_PATH)
            except FileNotFoundError:
                continue
            except FileExistsError:
                pass
            break
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
        with LOCK:
            db = read_database()
            db["relay_catalog_override"] = catalog
            write_database(db)
        return catalog
    with LOCK:
        db = read_database()
        settings = db.get("wireguard", {})
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
                    address = str(ipaddress.IPv4Interface(address))
                except (ValueError, binascii.Error):
                    raise ValueError("Enter a valid WireGuard private key and IPv4 address with prefix.") from None
                db["wireguard"] = {"address": address, "key": key}
                write_database(db)
                result = {"address": address, "hasKey": True}
                if payload.get("includeKey") is True:
                    result["key"] = key
                return result
        if path == "/dashboard/provision" and method == "POST":
            if not settings.get("key"):
                raise ValueError("Save your WireGuard settings first.")
            relay = next((row for row in current_catalog(db) if row["name"] == payload.get("name")), None)
            if relay is None:
                raise ValueError("Relay is missing from the local catalog.")
            return {"relay": relay, "address": settings["address"], "key": settings["key"]}
    raise LookupError
