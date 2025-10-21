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
MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50 MB
MIN_MTU = 1
MAX_MTU = 65535
PROCESS_TTL_SECONDS = int(os.getenv("PROCESS_TTL_SECONDS", str(30 * 60)))  # 1800s por defecto

# Tabla ARP simulada (IP -> MAC)
MAC_TABLE = {
    "10.0.0.1": "0A:00:00:01",
    "10.0.0.2": "0A:00:00:02",
    "default": "0A:FF:FF:01",
}
BROADCAST_MAC = "FF:FF:FF:FF:FF:FF"
BROADCAST_IPS = ["255.255.255.255", "10.0.0.255"]


# =========================
# App y templates
# =========================
app = FastAPI()

if os.path.isdir("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")

templates = Jinja2Templates(directory="templates")

# Almacén en memoria:
PROCESS_STORE: Dict[str, Dict[str, Any]] = {}


# =========================
# Capas (helpers)
# =========================
def presentation_layer(payload_text: Optional[str], file_bytes: Optional[bytes]) -> dict:
    """
    (Capa 6) Devuelve un diccionario con el payload en base64 y metadatos.
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
    (Capa 4) Fragmenta el payload (bytes) respetando el MTU.
    """
    if mtu is None or mtu <= 0:
        mtu = MIN_MTU
    mtu = max(MIN_MTU, min(int(mtu), MAX_MTU))

    payload_b64: str = pres["payload_b64"]
    payload_bytes = base64.b64decode(payload_b64.encode("ascii"))
    
    chunks = [payload_bytes[i:i + mtu] for i in range(0, len(payload_bytes), mtu)]
    if not payload_bytes:
        chunks = [b""]
    total = len(chunks)

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
    (Capa 3) Produce paquetes de red inyectando cabecera de red.
    """
    packets_by_dst: Dict[str, List[dict]] = {}
    for dst in dst_ips:
        packets = []
        for seg in transport_segments:
            net_header = {
                "src_ip": src_ip,
                "dst_ip": dst,
                "protocol": "SIMPROTO/1.0",
                "ttl": 64,
            }
            packets.append({
                "network_header": net_header,
                **seg,
            })
        packets_by_dst[dst] = packets
    return packets_by_dst


def data_link_layer(
    packets_by_dst: Dict[str, List[dict]]
) -> Dict[str, List[dict]]:
    """
    (Capa 2) Envuelve los paquetes en tramas, añadiendo cabeceras MAC.
    """
    frames_by_dst: Dict[str, List[dict]] = {}
    
    for dst_ip, packets in packets_by_dst.items():
        frames = []
        src_mac = MAC_TABLE.get(packets[0]["network_header"]["src_ip"], MAC_TABLE["default"])
        
        for p in packets:
            transmission_type = "Unicast"
            if dst_ip in BROADCAST_IPS:
                dst_mac = BROADCAST_MAC
                transmission_type = "Broadcast"
            else:
                dst_mac = MAC_TABLE.get(dst_ip, MAC_TABLE["default"])
            link_header = {
                "src_mac": src_mac,
                "dst_mac": dst_mac,
                "type": "SIMv4",
                "transmission_type": transmission_type 
            }
            frames.append({
                "data_link_header": link_header,
                **p,
            })
        frames_by_dst[dst_ip] = frames
        
    return frames_by_dst


# =================================================================
# LÓGICA DE RESUMEN Y PASOS (Encapsulación y Desencapsulación)
# =================================================================

def build_summary(
    pres: dict, 
    transport_segments: list, 
    packets_by_dst: dict, 
    frames_by_dst: dict,
    mtu: int
) -> dict:
    
    total_raw_len = pres.get("size", 0)
    frag_count = len(transport_segments)
    net_packets = sum(len(v) for v in packets_by_dst.values())
    link_frames = sum(len(v) for v in frames_by_dst.values())
    
    first_frame = {}
    if link_frames > 0:
        first_dst_ip = list(frames_by_dst.keys())[0]
        first_frame = frames_by_dst[first_dst_ip][0].get("data_link_header", {})
    
    first_packet = {}
    if net_packets > 0:
        first_dst_ip = list(packets_by_dst.keys())[0]
        first_packet = packets_by_dst[first_dst_ip][0].get("network_header", {})

    return {
        # --- Computadora Origen ---
        "Application": {"ui": "Entrada recibida (texto o archivo)"},
        "Presentation": {
            "type": "text" if pres.get("content_type", "").startswith("text/") else "binary",
            "raw_bytes_len": total_raw_len,
            "encoding": "utf-8 + base64" if pres.get("content_type", "").startswith("text/") else "base64",
        },
        "Session": {
            "info": "Sesión iniciada (controlada por process_id y TTL)"
        },
        "Transport": {
            "requested_mtu": mtu,
            "total_len": total_raw_len,
            "fragments_count": frag_count,
            "fragments_info": [
                f"segmento {seg['transport_header']['seq']}/{seg['transport_header']['total']} "
                f"(payload: {len(base64.b64decode(seg['payload_b64']))} bytes)"
                for seg in transport_segments
            ],
        },
        "Network": {
            "total_packets": net_packets,
            "protocol": "SIMPROTO/1.0",
            "src_ip": first_packet.get("src_ip", "N/A"),
            "dst_ip": first_packet.get("dst_ip", "N/A"),
        },
        "DataLink": {
            "total_frames": link_frames,
            "src_mac": first_frame.get("src_mac", "N/A"),
            "dst_mac": first_frame.get("dst_mac", "N/A"),
            "transmission_type": first_frame.get("transmission_type", "N/A")
        },
        "Physical": {"logs": ["Transmisión simulada de tramas (bits)..."]},
        
        # --- Computadora Destino ---
        "Receiver": {
            "dst_ip": first_packet.get("dst_ip", "N/A"),
            "dst_mac": first_frame.get("dst_mac", "N/A")
        }
    }


def build_encapsulation_steps(summary: dict) -> List[dict]:
    """Genera los pasos de ENVÍO (Capas 7 a 1)"""
    src_ip = summary["Network"]["src_ip"]
    return [
        {"title": f"ENVÍO (Origen: {src_ip})", "detail": "Inicio del proceso de encapsulación..."},
        {"title": "Capa 7: Application (Interfaz de Usuario)", 
         "detail": summary["Application"]["ui"]},
        {"title": "Capa 6: Presentation (Codificador)", 
         "detail": f"Tipo: {summary['Presentation']['type']}\nTamaño: {summary['Presentation']['raw_bytes_len']} bytes\nCodificación: {summary['Presentation']['encoding']}"},
        {"title": "Capa 5: Session (Control)",
         "detail": summary["Session"]["info"]},
        {"title": "Capa 4: Transport (Segmentación)", 
         "detail": f"Encabezado de Transporte añadido:\nMTU: {summary['Transport']['requested_mtu']} bytes\nSegmentos: {summary['Transport']['fragments_count']}\n" + "\n".join(summary['Transport']['fragments_info'])},
        {"title": "Capa 3: Network (Paquetes)", 
         "detail": f"Encabezado de Red añadido:\nProtocolo: {summary['Network']['protocol']}\nPaquetes: {summary['Network']['total_packets']}\nIP Origen: {summary['Network']['src_ip']}\nIP Destino: {summary['Network']['dst_ip']}"},
        {"title": "Capa 2: Data Link (Tramas)", 
         "detail": f"Encabezado de Enlace añadido:\nTramas: {summary['DataLink']['total_frames']}\nTipo: {summary['DataLink']['transmission_type']}\nMAC Origen: {summary['DataLink']['src_mac']}\nMAC Destino: {summary['DataLink']['dst_mac']}"},
        {"title": "Capa 1: Physical (Transmisión)", 
         "detail": summary["Physical"]["logs"][0]},
    ]

def build_decapsulation_steps(summary: dict) -> List[dict]:
    """Genera los pasos de RECEPCIÓN (Capas 1 a 7)"""
    dst_ip = summary["Receiver"]["dst_ip"]
    dst_mac = summary["Receiver"]["dst_mac"]
    
    return [
        {"title": f"RECEPCIÓN (Destino: {dst_ip})", "detail": "Inicio del proceso de desencapsulación..."},
        {"title": "Capa 1: Physical (Recepción)", 
         "detail": f"Se reciben bits del medio y se agrupan para formar tramas."},
        {"title": "Capa 2: Data Link (Desencapsulado)", 
         "detail": f"Se lee el encabezado de Enlace.\n¿Es esta MAC para mí? ({dst_mac}) -> SÍ.\nSe quita el encabezado de enlace y se pasa el paquete a la Capa 3."},
        {"title": "Capa 3: Network (Desencapsulado)", 
         "detail": f"Se lee el encabezado de Red.\n¿Es esta IP para mí? ({dst_ip}) -> SÍ.\nSe quita el encabezado de red y se pasa el segmento a la Capa 4."},
        {"title": "Capa 4: Transport (Reensamblado)", 
         "detail": f"Se leen los encabezados de Transporte (seq 1, 2, 3...).\nSe reensamblan los {summary['Transport']['fragments_count']} segmentos en orden.\nSe entrega el bloque de datos a la Capa 5."},
        {"title": "Capa 5: Session (Control)",
         "detail": "Se gestiona la sesión (se confirma la recepción de datos)."},
        {"title": "Capa 6: Presentation (Decodificador)", 
         "detail": f"Se decodifican los datos (Base64 -> {summary['Presentation']['type']})\nDatos listos para la aplicación."},
        {"title": "Capa 7: Application (Entrega)", 
         "detail": "Los datos reensamblados y decodificados se entregan a la aplicación final (ej. el navegador, un visor de imágenes)."},
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
    text: Optional[str] = Form(None),
    file: UploadFile = File(None),
    mtu: int = Form(50),
    src_ip: str = Form("10.0.0.1"),
    dst_ip: str = Form("10.0.0.2"),
):
    # Normaliza texto
    payload_text = payload_text if (payload_text and payload_text.strip()) else (
        text if (text and text.strip()) else None
    )

    # Lee archivo
    file_bytes = None
    if file is not None:
        file_bytes = await file.read()
        if file_bytes and len(file_bytes) > MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail=f"Archivo demasiado grande ({len(file_bytes) // 1024} KB). Límite: {MAX_UPLOAD_BYTES // 1024} KB")

    # --- SIMULACIÓN DE CAPAS (ENCAPSULACIÓN) ---
    pres = presentation_layer(payload_text, file_bytes)           # Capa 6
    transport_segments = transport_layer(pres, mtu)               # Capa 4
    targets = [dst_ip or "10.0.0.2"]
    packets_by_dst = network_layer_by_destination(                # Capa 3
        transport_segments=transport_segments,
        src_ip=src_ip,
        dst_ips=targets,
    )
    frames_by_dst = data_link_layer(packets_by_dst)               # Capa 2

    # Meta y expiración
    created = time.time()
    expires = created + PROCESS_TTL_SECONDS

    # Summary / Steps
    summary = build_summary(pres, transport_segments, packets_by_dst, frames_by_dst, mtu)
    
    # Pasos: encapsulación + decapsulación
    encapsulation_steps = build_encapsulation_steps(summary)
    decapsulation_steps = build_decapsulation_steps(summary)
    steps = encapsulation_steps + decapsulation_steps

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
                "frames": frames_by_dst[dst],
                "transport_total": len(transport_segments),
                "reassembled": None,
            }
            for dst in targets
        },
        "summary": summary,
        "steps": steps,
    }

    deliveries_summary = [
        {"dst_ip": d, "fragments": len(PROCESS_STORE[pid]["deliveries"][d]["frames"])}
        for d in targets
    ]
    first_dst = targets[0]

    return {
        "pid": pid,
        "meta": PROCESS_STORE[pid]["meta"],
        "deliveries_summary": deliveries_summary,
        "fragments": PROCESS_STORE[pid]["deliveries"][first_dst]["frames"],
        "summary": summary,
        "steps": steps,
        "expires_in": max(0, int(expires - time.time())),
    }


@app.post("/reassemble")
async def reassemble(pid: str = Form(None), dst_ip: str = Form(None)):
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

    frames = deliveries[dst_ip].get("frames", [])

    try:
        frames_sorted = sorted(
            frames,
            key=lambda f: f.get("transport_header", {}).get("seq", 0)
        )
    except Exception:
        frames_sorted = frames

    parts: List[bytes] = []
    for f in frames_sorted:
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
    if not payload or not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail={"error": "invalid_payload", "message": "Se requiere un JSON en el cuerpo"})

    frames = payload.get("frames") or payload.get("fragments") or []
    
    if not isinstance(frames, list) or len(frames) == 0:
        raise HTTPException(status_code=400, detail={"error": "no_fragments", "message": "No se recibieron frames/fragments"})

    try:
        frames_sorted = sorted(frames, key=lambda f: f.get("transport_header", {}).get("seq", 0))
    except Exception:
        frames_sorted = frames

    parts: List[bytes] = []
    for f in frames_sorted:
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
        {"dst_ip": d, "fragments": len(item["deliveries"][d]["frames"])}
        for d in targets
    ]
    first_dst = targets[0]

    return {
        "pid": pid,
        "meta": item["meta"],
        "deliveries_summary": deliveries_summary,
        "fragments": item["deliveries"][first_dst]["frames"],
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

    targets = item["meta"]["dst_ips"]
    if not dst_ip:
        dst_ip = targets[0]
    if dst_ip not in item["deliveries"]:
        return JSONResponse({"error": "destination_not_found", "message": "Destino no encontrado"}, status_code=404)

    frames = item["deliveries"][dst_ip].get("frames", [])

    try:
        frames_sorted = sorted(frames, key=lambda f: f.get("transport_header", {}).get("seq", 0))
    except Exception:
        frames_sorted = frames

    parts: List[bytes] = []
    for f in frames_sorted:
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


# Limpieza periódica
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