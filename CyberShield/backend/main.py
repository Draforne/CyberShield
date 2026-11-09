
import os
import json
import socket
import struct
import hashlib
import requests

from datetime import datetime, timezone

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from sqlalchemy import (
    create_engine, Column, Integer, String,
    DateTime, Text, JSON
)
from sqlalchemy.orm import declarative_base, sessionmaker

# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://cyber:cyberpass@localhost:5432/cybershield"
)

CLAMAV_HOST = os.getenv("CLAMAV_HOST", "clamav")
CLAMAV_PORT = int(os.getenv("CLAMAV_PORT", "3310"))

MAX_FILE_SIZE = 50 * 1024 * 1024
BRIDGE_TOKEN = os.getenv("BRIDGE_TOKEN", "change-me")

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
Session = sessionmaker(bind=engine)
Base = declarative_base()

app = FastAPI(
    title="CyberShield API",
    description="Plateforme de cybersécurité défensive",
    version="1.0.0"
)
@app.exception_handler(Exception)
async def debug_exception(request, exc):
    import traceback

    traceback.print_exc()

    from fastapi.responses import JSONResponse

    return JSONResponse(
        status_code=500,
        content={"detail": str(exc)}
    )
# --------------------------------------------------
# DATABASE MODELS
# --------------------------------------------------

class FileScan(Base):
    __tablename__ = "file_scans"

    id = Column(Integer, primary_key=True)
    filename = Column(String(255))
    sha256 = Column(String(64))
    status = Column(String(50))
    details = Column(Text)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )


class CVE(Base):
    __tablename__ = "cves"

    id = Column(Integer, primary_key=True)
    cve_id = Column(String(30), unique=True, index=True)
    description = Column(Text)
    cvss = Column(String(20))
    severity = Column(String(30))
    solution = Column(Text)
    references = Column(JSON)
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )


class DeviceScan(Base):
    __tablename__ = "device_scans"

    id = Column(Integer, primary_key=True)
    device_type = Column(String(30))
    device_name = Column(String(255))
    address = Column(String(100))
    signal = Column(Integer, nullable=True)
    details = Column(JSON)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )


Base.metadata.create_all(bind=engine)

# --------------------------------------------------
# GENERAL
# --------------------------------------------------

@app.get("/")
def home():
    return FileResponse("/app/static/index.html")


@app.get("/api/status")
def status():
    db = Session()
    try:
        db.execute(__import__("sqlalchemy").text("SELECT 1"))
        return {
            "status": "online",
            "database": "connected",
            "antivirus": "ClamAV",
            "version": "1.0.0"
        }
    finally:
        db.close()


# --------------------------------------------------
# ANTIVIRUS
# --------------------------------------------------


def scan_with_clamav(data: bytes):
    try:
        with socket.create_connection(
            (CLAMAV_HOST, CLAMAV_PORT),
            timeout=60
        ) as sock:

            sock.settimeout(120)

            # Initialisation du protocole INSTREAM
            sock.sendall(b"zINSTREAM\0")

            chunk_size = 2048

            # Transmission des données binaires originales
            for offset in range(0, len(data), chunk_size):
                chunk = data[offset:offset + chunk_size]

                sock.sendall(struct.pack("!I", len(chunk)))
                sock.sendall(chunk)

            # Fin du flux
            sock.sendall(struct.pack("!I", 0))

            # Lire toute la réponse jusqu'au terminateur
            response_data = bytearray()

            while True:
                part = sock.recv(4096)

                if not part:
                    break

                response_data.extend(part)

                if b"\0" in response_data or b"\n" in response_data:
                    break

                if len(response_data) > 65536:
                    return "error", "Réponse ClamAV trop volumineuse"

            response = response_data.decode(
                "utf-8", errors="replace"
            ).strip("\x00\r\n ")

            if "FOUND" in response:
                return "infected", response

            if "OK" in response:
                return "clean", response

            return "error", response or "Réponse ClamAV vide"

    except (OSError, TimeoutError) as exc:
        return "error", f"Erreur de connexion ClamAV : {exc}"




@app.post("/api/scan/file")
async def scan_file(file: UploadFile = File(...)):
    filename = os.path.basename(file.filename or "unknown")

    if "\x00" in filename:
        raise HTTPException(400, "Nom de fichier invalide")

    if len(filename) > 255:
        raise HTTPException(400, "Nom de fichier trop long")

    data = await file.read(MAX_FILE_SIZE + 1)

    if not data:
        raise HTTPException(400, "Fichier vide")

    if len(data) > MAX_FILE_SIZE:
        raise HTTPException(413, "Fichier trop volumineux (50 Mo max)")

    sha256 = hashlib.sha256(data).hexdigest()

    # Analyse ClamAV
    status, details = scan_with_clamav(data)

    # Vérification des données textuelles avant PostgreSQL
    if isinstance(status, bytes):
        status = status.decode("utf-8", errors="replace")

    if isinstance(details, bytes):
        details = details.decode("utf-8", errors="replace")

    status = str(status or "error")
    details = str(details or "")

    filename = filename.replace("\x00", "\\x00")
    status = status.replace("\x00", "\\x00")
    details = details.replace("\x00", "\\x00")

    if len(status) > 50:
        status = status[:50]

    db = Session()

    try:
        record = FileScan(
            filename=filename,
            sha256=sha256,
            status=status,
            details=details
        )

        db.add(record)
        db.commit()
        db.refresh(record)

        return {
            "id": record.id,
            "filename": filename,
            "sha256": sha256,
            "status": status,
            "details": details,
            "created_at": record.created_at.isoformat()
        }

    except Exception as exc:
        db.rollback()

        print(f"FILE SCAN DATABASE ERROR: {type(exc).__name__}: {exc}")

        raise HTTPException(
            status_code=500,
            detail="Erreur lors de l'enregistrement du scan"
        )

    finally:
        db.close()
        await file.close()



# --------------------------------------------------
# CVE / NATIONAL VULNERABILITY DATABASE
# --------------------------------------------------

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def get_solution(severity):
    solutions = {
        "CRITICAL": (
            "Priorité maximale : appliquer immédiatement "
            "les correctifs officiels, isoler le système "
            "si nécessaire et vérifier les indicateurs "
            "de compromission."
        ),
        "HIGH": (
            "Installer les correctifs de sécurité disponibles, "
            "réduire l'exposition du service et contrôler "
            "les journaux."
        ),
        "MEDIUM": (
            "Planifier une mise à jour, appliquer les mesures "
            "de réduction du risque et surveiller le service."
        ),
        "LOW": (
            "Maintenir le logiciel à jour et surveiller "
            "les recommandations de l'éditeur."
        )
    }

    return solutions.get(
        severity,
        "Consulter les recommandations officielles de l'éditeur."
    )


@app.get("/api/cves/search")
def search_cves(keyword: str = "", limit: int = 10):

    limit = max(1, min(limit, 50))

    params = {
        "resultsPerPage": limit
    }

    if keyword:
        params["keywordSearch"] = keyword

    try:
        response = requests.get(
            NVD_URL,
            params=params,
            timeout=25
        )
        response.raise_for_status()

    except requests.RequestException as exc:
        raise HTTPException(
            502, f"Service NVD indisponible : {exc}"
        )

    vulnerabilities = response.json().get("vulnerabilities", [])
    db = Session()

    results = []

    try:
        for item in vulnerabilities:
            cve = item.get("cve", {})
            cve_id = cve.get("id")

            descriptions = cve.get("descriptions", [])
            description = next(
                (
                    d.get("value", "")
                    for d in descriptions
                    if d.get("lang") == "en"
                ),
                "Description indisponible"
            )

            metrics = cve.get("metrics", {})
            cvss = None

            for metric_name in (
                "cvssMetricV40",
                "cvssMetricV31",
                "cvssMetricV30",
                "cvssMetricV2"
            ):
                metric_list = metrics.get(metric_name, [])

                if metric_list:
                    cvss_data = metric_list[0].get(
                        "cvssData", {}
                    )
                    cvss = cvss_data.get("baseScore")
                    severity = cvss_data.get(
                        "baseSeverity", "UNKNOWN"
                    )
                    break
            else:
                severity = "UNKNOWN"

            references = [
                ref.get("url")
                for ref in cve.get("references", [])
                if ref.get("url")
            ][:10]

            solution = get_solution(severity)

            existing = db.query(CVE).filter_by(
                cve_id=cve_id
            ).first()

            if existing:
                existing.description = description
                existing.cvss = str(cvss or "")
                existing.severity = severity
                existing.solution = solution
                existing.references = references
            else:
                db.add(CVE(
                    cve_id=cve_id,
                    description=description,
                    cvss=str(cvss or ""),
                    severity=severity,
                    solution=solution,
                    references=references
                ))

            results.append({
                "cve_id": cve_id,
                "description": description,
                "cvss": cvss,
                "severity": severity,
                "solution": solution,
                "references": references
            })

        db.commit()
        return {"count": len(results), "results": results}

    finally:
        db.close()


@app.get("/api/cves")
def get_saved_cves():
    db = Session()
    try:
        records = db.query(CVE).order_by(
            CVE.updated_at.desc()
        ).limit(200).all()

        return [
            {
                "cve_id": c.cve_id,
                "description": c.description,
                "cvss": c.cvss,
                "severity": c.severity,
                "solution": c.solution,
                "references": c.references
            }
            for c in records
        ]
    finally:
        db.close()


# --------------------------------------------------
# ESP32 DEVICE INGESTION
# --------------------------------------------------

@app.post("/api/devices/ingest")
def ingest_device(payload: dict, x_bridge_token: str = ""):

    if x_bridge_token != BRIDGE_TOKEN:
        raise HTTPException(401, "Bridge non autorisé")

    device_type = payload.get("type")

    if device_type not in ("wifi", "bluetooth"):
        raise HTTPException(400, "Type de périphérique invalide")

    name = str(payload.get("name", "Inconnu"))[:255]
    address = str(payload.get("address", "Inconnu"))[:100]

    signal = payload.get("rssi")

    if signal is not None:
        try:
            signal = int(signal)
        except (TypeError, ValueError):
            raise HTTPException(400, "RSSI invalide")

    db = Session()

    try:
        record = DeviceScan(
            device_type=device_type,
            device_name=name,
            address=address,
            signal=signal,
            details=payload
        )

        db.add(record)
        db.commit()

        return {"status": "saved", "id": record.id}
    finally:
        db.close()


@app.get("/api/devices")
def get_devices():
    db = Session()

    try:
        records = db.query(DeviceScan).order_by(
            DeviceScan.created_at.desc()
        ).limit(500).all()

        return [
            {
                "id": r.id,
                "type": r.device_type,
                "name": r.device_name,
                "address": r.address,
                "rssi": r.signal,
                "details": r.details,
                "created_at": r.created_at.isoformat()
            }
            for r in records
        ]
    finally:
        db.close()


# --------------------------------------------------
# HISTORY
# --------------------------------------------------

@app.get("/api/history")
def history():
    db = Session()

    try:
        scans = db.query(FileScan).order_by(
            FileScan.created_at.desc()
        ).limit(100).all()

        return [
            {
                "id": s.id,
                "filename": s.filename,
                "sha256": s.sha256,
                "status": s.status,
                "details": s.details,
                "created_at": s.created_at.isoformat()
            }
            for s in scans
        ]
    finally:
        db.close()


# --------------------------------------------------
# STATISTICS
# --------------------------------------------------

@app.get("/api/stats")
def stats():
    db = Session()

    try:
        return {
            "file_scans": db.query(FileScan).count(),
            "infected": db.query(FileScan).filter_by(
                status="infected"
            ).count(),
            "cves": db.query(CVE).count(),
            "devices": db.query(DeviceScan).count()
        }
    finally:
        db.close()


app.mount(
    "/static",
    StaticFiles(directory="/app/static"),
    name="static"
)
