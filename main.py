import os
import io
import time
import base64
import asyncio
import uuid
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, Request, UploadFile, File, Form, HTTPException, Body
from fastapi.responses import JSONResponse, HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates


# =========================
# Configuración y constantes
# =========================
MAX_UPLOAD_BYTES = 5 * 1024 * 1024  # 5 MB
MIN_MTU = 1
MAX_MTU = 65535
PROCESS_TTL_SECONDS = int(os.getenv("PROCESS_TTL_SECONDS", str(30 * 60)))  # 1800s por defecto


# =========================
# App y templates
# =========================
app = FastAPI()

if os.path.isdir("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")

templates = Jinja2Templates(directory="templates")

# Almacén en memoria:
# pid -> {
#   created: float, expires: float,
#   meta: {...},
#   deliveries: { dst_ip: { fragments: [...], transport_total: int, reassembled: Optional[bytes] } },
#   summary: dict, steps: list
# }
PROCESS_STORE: Dict[str, Dict[str, Any]] = {}


# =========================
# Capas (helpers)
# =========================
def presentation_layer(payload_text: Optional[str], file_bytes: Optional[bytes]) -> dict:
    """
    Devuelve un diccionario con el payload en base64 y metadatos.
    - Si viene texto, lo codifica UTF-8.
    - Si viene archivo, usa sus bytes.
    """
    if payload_text and payload_text.strip():
        raw = payload_text.encode("utf-8")
        ctype = "text/plain; charset=utf-8"
    elif file_bytes:
        raw = file_bytes
        ctype = "application/octet-stream"
    else:
        raise HTTPException(status_code=400, detail="Payload vacío")

    payload_b64 = base64.b64encode(raw).decode("ascii")
    return {
        "content_type": ctype,
        "size": len(raw),
        "payload_b64": payload_b64,
    }


def transport_layer(pres: dict, mtu: int) -> List[dict]:
    """
    Fragmenta el payload (bytes) respetando el MTU.
    Devuelve segmentos con header de transporte y el chunk en base64.
    """
    if mtu is None or mtu <= 0:
        mtu = MIN_MTU
    mtu = max(MIN_MTU, min(int(mtu), MAX_MTU))

    payload_b64: str = pres["payload_b64"]
    payload_bytes = base64.b64decode(payload_b64.encode("ascii"))

    chunks = [payload_bytes[i:i + mtu] for i in range(0, len(payload_bytes), mtu)]
    total = len(chunks) if chunks else 1

    segments: List[dict] = []
    for i, ch in enumerate(chunks, start=1):
        segments.append({
            "transport_header": {
                "seq": i,
                "total": total,
                "mtu": mtu,
            },
            "payload_b64": base64.b64encode(ch).decode("ascii"),
        })
    return segments


def network_layer_by_destination(
    transport_segments: List[dict],
    src_ip: str,
    dst_ips: List[str],
) -> Dict[str, List[dict]]:
    """
    Produce paquetes de red (una copia por destino) inyectando cabecera de red.
    (Simplificado a unicast: normalmente dst_ips tendrá un solo elemento)
    """
    packets_by_dst: Dict[str, List[dict]] = {}
    for dst in dst_ips:
        packets = []
        for seg in transport_segments:
            net_header = {
                "src_ip": src_ip,
                "dst_ip": dst,
                "protocol": "SIMPROTO/1.0",
            }
            packets.append({
                "network_header": net_header,
                **seg,  # mantiene transport_header y payload_b64
            })
        packets_by_dst[dst] = packets
    return packets_by_dst


def build_summary(pres: dict, transport_segments: list, packets_by_dst: dict, mtu: int) -> dict:
    total_raw_len = pres.get("size", 0)
    frag_count = len(transport_segments)
    net_frags = sum(len(v) for v in packets_by_dst.values())
    return {
        "Application": {"ui": "Entrada recibida"},
        "Presentation": {
            "type": "text" if pres.get("content_type", "").startswith("text/") else "binary",
            "raw_bytes_len": total_raw_len,
            "encoding": "utf-8 + base64" if pres.get("content_type", "").startswith("text/") else "base64",
        },
        "Transport": {
            "requested_mtu": mtu,
            "total_len": total_raw_len,
            "fragments_count": frag_count,
            "fragments": [
                f"fragment {seg['transport_header']['seq']}/{seg['transport_header']['total']} "
                f"len={len(base64.b64decode(seg['payload_b64']))}"
                for seg in transport_segments
            ],
        },
        "Network": {"network_fragments": net_frags},
        "Physical": {"logs": ["1 entries"]},
    }


def build_steps(summary: dict) -> List[dict]:
    return [
        {"title": "Application (Interfaz de Usuario)", "detail": summary["Application"]["ui"]},
        {"title": "Presentation (Codificador)", "detail": f"type: {summary['Presentation']['type']}"},
        {"title": "Transport", "detail": f"fragments: {summary['Transport']['fragments_count']}"},
        {"title": "Network", "detail": f"network_fragments: {summary['Network']['network_fragments']}"},
        {"title": "Physical (Transmisión Visual)", "detail": f"logs: {summary['Physical']['logs'][0]}"},
    ]


# =========================
# Rutas
# =========================
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    try:
        return templates.TemplateResponse("index.html", {"request": request})
    except Exception:
        html = """
        <html><body>
        <h2>Simulador de Protocolo</h2>
        <p>La plantilla no está disponible. Prueba /health para comprobar el servicio.</p>
        </body></html>
        """
        return HTMLResponse(html, status_code=200)


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/process")
async def process(
    payload_text: Optional[str] = Form(None),
    text: Optional[str] = Form(None),             # alias por compatibilidad
    file: UploadFile = File(None),
    mtu: int = Form(20),
    src_ip: str = Form("10.0.0.1"),
    dst_ip: str = Form("10.0.0.2"),
):
    # Normaliza texto
    payload_text = payload_text if (payload_text and payload_text.strip()) else (
        text if (text and text.strip()) else None
    )

    # Lee archivo (si viene)
    file_bytes = None
    if file is not None:
        file_bytes = await file.read()
        if file_bytes and len(file_bytes) > MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail="Archivo demasiado grande")

    # Capas
    pres = presentation_layer(payload_text, file_bytes)
    transport_segments = transport_layer(pres, mtu)

    # Destino único (unicast simple)
    targets = [dst_ip or "10.0.0.2"]

    packets_by_dst = network_layer_by_destination(
        transport_segments=transport_segments,
        src_ip=src_ip,
        dst_ips=targets,
    )

    # Meta y expiración
    created = time.time()
    expires = created + PROCESS_TTL_SECONDS

    # Summary / Steps
    summary = build_summary(pres, transport_segments, packets_by_dst, mtu)
    steps = build_steps(summary)

    # Persistencia
    pid = str(uuid.uuid4())
    PROCESS_STORE[pid] = {
        "created": created,
        "expires": expires,
        "meta": {
            "src_ip": src_ip,
            "dst_ips": targets,
            "mtu": mtu,
        },
        "deliveries": {
            dst: {
                "fragments": packets_by_dst[dst],
                "transport_total": len(transport_segments),
                "reassembled": None,
            }
            for dst in targets
        },
        "summary": summary,
        "steps": steps,
    }

    # Resumen por destino
    deliveries_summary = [
        {"dst_ip": d, "fragments": len(PROCESS_STORE[pid]["deliveries"][d]["fragments"])}
        for d in targets
    ]
    first_dst = targets[0]

    return {
        "pid": pid,
        "meta": PROCESS_STORE[pid]["meta"],
        "deliveries_summary": deliveries_summary,
        # Compat: fragments del primer destino para la UI actual
        "fragments": PROCESS_STORE[pid]["deliveries"][first_dst]["fragments"],
        "summary": summary,
        "steps": steps,
        "expires_in": max(0, int(expires - time.time())),
    }


@app.post("/reassemble")
async def reassemble(pid: str = Form(None), dst_ip: str = Form(None)):
    """
    Reensambla por destino. Si no se envía dst_ip, usa el primero.
    """
    if not pid:
        raise HTTPException(status_code=400, detail={"error": "missing_pid", "message": "pid es requerido"})

    proc = PROCESS_STORE.get(pid)
    if not proc:
        raise HTTPException(status_code=404, detail={"error": "not_found", "message": "process_id no existe"})

    if proc.get("expires", 0) <= time.time():
        PROCESS_STORE.pop(pid, None)
        raise HTTPException(status_code=404, detail={"error": "expired", "message": "process_id expirado"})

    deliveries = proc.get("deliveries", {})
    if not deliveries:
        raise HTTPException(status_code=400, detail={"error": "no_deliveries", "message": "No hay entregas para este proceso"})

    if not dst_ip:
        dst_ip = proc["meta"]["dst_ips"][0]

    if dst_ip not in deliveries:
        raise HTTPException(status_code=404, detail={"error": "destination_not_found", "message": "Destino no encontrado"})

    fragments = deliveries[dst_ip]["fragments"]

    # Ordena por seq si existe
    try:
        fragments_sorted = sorted(
            fragments,
            key=lambda f: f.get("transport_header", {}).get("seq", 0)
        )
    except Exception:
        fragments_sorted = fragments

    parts: List[bytes] = []
    for f in fragments_sorted:
        p_b64 = f.get("payload_b64", "")
        if not p_b64:
            continue
        try:
            part = base64.b64decode(p_b64.encode("ascii"))
        except Exception:
            part = b""
        parts.append(part)

    reassembled_bytes = b"".join(parts)
    deliveries[dst_ip]["reassembled"] = reassembled_bytes

    return {"pid": pid, "dst_ip": dst_ip, "status": "ok", "size": len(reassembled_bytes)}


@app.post("/download")
async def download(payload: Dict[str, Any] = Body(None)):
    """
    Recibe { fragments: [...] } y devuelve el contenido reensamblado como attachment.
    """
    if not payload or not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail={"error": "invalid_payload", "message": "Se requiere un JSON en el cuerpo"})

    fragments = payload.get("fragments") or []
    if not isinstance(fragments, list) or len(fragments) == 0:
        raise HTTPException(status_code=400, detail={"error": "no_fragments", "message": "No se recibieron fragments"})

    try:
        fragments_sorted = sorted(fragments, key=lambda f: f.get("transport_header", {}).get("seq", 0))
    except Exception:
        fragments_sorted = fragments

    parts: List[bytes] = []
    for f in fragments_sorted:
        p_b64 = f.get("payload_b64", "")
        if not p_b64:
            continue
        try:
            part = base64.b64decode(p_b64.encode("ascii"))
        except Exception:
            part = b""
        parts.append(part)

    reassembled_bytes = b"".join(parts)
    if len(reassembled_bytes) == 0:
        raise HTTPException(status_code=400, detail={"error": "empty_payload", "message": "El payload reensamblado está vacío"})

    filename = payload.get("filename") or "reassembled.bin"
    content_type = "text/plain; charset=utf-8" if payload.get("type") == "text" else "application/octet-stream"

    stream = io.BytesIO(reassembled_bytes)
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    return StreamingResponse(stream, media_type=content_type, headers=headers)


@app.get("/result/{pid}")
async def get_result(pid: str):
    item = PROCESS_STORE.get(pid)
    if not item:
        raise HTTPException(status_code=404, detail={"error": "not_found", "message": "process_id no existe"})
    if item.get("expires", 0) <= time.time():
        PROCESS_STORE.pop(pid, None)
        raise HTTPException(status_code=404, detail={"error": "expired", "message": "process_id expirado"})

    targets = item["meta"]["dst_ips"]
    deliveries_summary = [
        {"dst_ip": d, "fragments": len(item["deliveries"][d]["fragments"])}
        for d in targets
    ]
    first_dst = targets[0]

    return {
        "pid": pid,
        "meta": item["meta"],
        "deliveries_summary": deliveries_summary,
        "fragments": item["deliveries"][first_dst]["fragments"],  # compat
        "summary": item.get("summary"),
        "steps": item.get("steps"),
        "expires_in": max(0, int(item["expires"] - time.time())),
        "created": item["created"],
        "expires": item["expires"],
    }


@app.get("/download/{pid}")
async def download_by_id(pid: str, dst_ip: Optional[str] = None):
    item = PROCESS_STORE.get(pid)
    if not item:
        return JSONResponse({"error": "not_found", "message": "process_id no existe"}, status_code=404)
    if item.get("expires", 0) <= time.time():
        PROCESS_STORE.pop(pid, None)
        return JSONResponse({"error": "expired", "message": "process_id expirado"}, status_code=404)

    # Selección de destino
    targets = item["meta"]["dst_ips"]
    if not dst_ip:
        dst_ip = targets[0]
    if dst_ip not in item["deliveries"]:
        return JSONResponse({"error": "destination_not_found", "message": "Destino no encontrado"}, status_code=404)

    fragments = item["deliveries"][dst_ip]["fragments"]

    try:
        fragments_sorted = sorted(fragments, key=lambda f: f.get("transport_header", {}).get("seq", 0))
    except Exception:
        fragments_sorted = fragments

    parts: List[bytes] = []
    for f in fragments_sorted:
        p_b64 = f.get("payload_b64", "")
        if not p_b64:
            continue
        try:
            part = base64.b64decode(p_b64.encode("ascii"))
        except Exception:
            part = b""
        parts.append(part)
    reassembled_bytes = b"".join(parts)

    if len(reassembled_bytes) == 0:
        raise HTTPException(status_code=400, detail={"error": "empty_payload", "message": "El payload reensamblado está vacío"})

    content_type = "application/octet-stream"
    filename = f"reassembled_{dst_ip}.bin"

    stream = io.BytesIO(reassembled_bytes)
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    return StreamingResponse(stream, media_type=content_type, headers=headers)


# =========================
# Limpieza periódica (background)
# =========================
async def _cleanup_expired_processes(interval: int = 60):
    while True:
        try:
            now = time.time()
            expired = [pid for pid, item in PROCESS_STORE.items() if item.get("expires", 0) <= now]
            for pid in expired:
                PROCESS_STORE.pop(pid, None)
            await asyncio.sleep(interval)
        except asyncio.CancelledError:
            break
        except Exception:
            await asyncio.sleep(interval)


@app.on_event("startup")
async def start_cleanup_task():
    app.state._process_cleanup_task = asyncio.create_task(_cleanup_expired_processes(60))


@app.on_event("shutdown")
async def stop_cleanup_task():
    task = getattr(app.state, "_process_cleanup_task", None)
    if task:
        task.cancel()
        try:
            await task
        except Exception:
            pass
