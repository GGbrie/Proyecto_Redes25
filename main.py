import os
from fastapi import FastAPI, Request, UploadFile, File, Form, HTTPException
from fastapi.responses import JSONResponse, HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import base64
import math
import io
from typing import Optional,List, Dict, Any
from fastapi import Body
import uuid
import time
import asyncio

from enum import Enum
from typing import List, Dict
import uuid

class TransmissionType(str, Enum):
    unicast = "unicast"
    broadcast = "broadcast"
    multicast = "multicast"


app = FastAPI()
# Montar static solo si existe para evitar errores al iniciar
if os.path.isdir("static"):
	app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Nuevo: límites de seguridad/configuración
MAX_UPLOAD_BYTES = 5 * 1024 * 1024  # 5 MB máximo por upload (ajusta si lo necesitas)
MIN_MTU = 1
MAX_MTU = 65535

# Almacén en memoria simple: id -> dict {created, response, fragments, type, filename, expires}
PROCESS_STORE: Dict[str, Dict[str, Any]] = {}

# Nuevo: TTL para procesos en segundos (leer de variable de entorno si está definida)
PROCESS_TTL_SECONDS = int(os.getenv("PROCESS_TTL_SECONDS", str(30 * 60)))  # por defecto 1800s (30 minutos)

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
        mtu = 1

    payload_b64 = pres["payload_b64"]
    # AQUI era donde tronaba: asegúrate que sea string SIEMPRE (ya lo garantizamos arriba)
    payload_bytes = base64.b64decode(payload_b64.encode("ascii"))

    chunks = [payload_bytes[i:i+mtu] for i in range(0, len(payload_bytes), mtu)]
    total = len(chunks) if chunks else 1

    segments: List[dict] = []
    for i, ch in enumerate(chunks, start=1):
        segments.append({
            "transport_header": {
                "seq": i,
                "total": total,
                "mtu": mtu
            },
            "payload_b64": base64.b64encode(ch).decode("ascii")
        })
    return segments


def network_layer(fragments, src_ip="10.0.0.1", dst_ip="192.168.1.100"):
	# Añade encabezados de red a cada fragmento
	net_fragments = []
	for f in fragments:
		net_header = {
			"src_ip": src_ip,
			"dst_ip": dst_ip,
			"protocol": "SIMPROTO/1.0"
		}
		combined = {"network_header": net_header, "transport": f}
		net_fragments.append(combined)
	return net_fragments

def network_layer_by_destination(
    transport_segments: List[dict],
    src_ip: str,
    dst_ips: List[str],
    transmission_type: TransmissionType
) -> Dict[str, List[dict]]:
    """
    Llama tu network_layer original para cada destino y agrega metadata mínima.
    Estructura devuelta:
    {
    "10.0.0.2": [ { "network_header": {...}, "transport": {...}, ... }, ... ],
    "10.0.0.3": [ ... ]
    }
    """
    packets_by_dst: Dict[str, List[dict]] = {}
    for dst in dst_ips:
        packets = []
        for seg in transport_segments:
            # Ajusta según tu estructura interna:
            net_header = {
                "src_ip": src_ip,
                "dst_ip": dst,
                "protocol": "SIMPROTO/1.0",
                "transmission_type": transmission_type.value
            }
            # Merge con tu estructura (asumo seg tiene transport_header y payload)
            packets.append({
                "network_header": net_header,
                **seg
            })
        packets_by_dst[dst] = packets
    return packets_by_dst


def resolve_targets(
    transmission_type: TransmissionType,
    dst_ip: str | None,
    dst_list: str | None
) -> List[str]:
    """
    Devuelve la lista de destinos final según el tipo:
    - unicast: [dst_ip]
    - broadcast: ["255.255.255.255"]
    - multicast: lista a partir de dst_list (separada por coma/espacio/nueva línea)
    """
    if transmission_type == TransmissionType.broadcast:
        return ["255.255.255.255"]

    if transmission_type == TransmissionType.multicast:
        raw = (dst_list or "").replace(";", ",").replace("\n", ",").replace("\t", ",")
        parts = [p.strip() for p in raw.split(",") if p.strip()]
        # Evita duplicados y direcciones inválidas sueltas
        uniq = []
        for p in parts:
            if p not in uniq:
                uniq.append(p)
        return uniq if uniq else ["239.0.0.1"]  # fallback multicast

    # Unicast (default)
    return [dst_ip or "10.0.0.2"]


def physical_layer_simulation(net_fragments):
	# Simula logs de transmisión física (no envía nada realmente)
	logs = []
	for nf in net_fragments:
		ts = f"TX fragment {nf['transport']['header']['transport_seq']}/{nf['transport']['header']['transport_total']} -> {nf['network_header']['dst_ip']}"
		logs.append(ts)
	return logs

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
	# Intentar renderizar la plantilla; si falla, devolver fallback simple
	try:
		return templates.TemplateResponse("index.html", {"request": request})
	except Exception:
		html = """<html><body><h2>Simulador de Protocolo</h2><p>La plantilla no está disponible. Prueba /health para comprobar el servicio.</p></body></html>"""
		return HTMLResponse(html, status_code=200)

# Almacén en memoria simple: id -> dict {created, response, fragments, type, filename}
PROCESS_STORE: Dict[str, Dict[str, Any]] = {}

from fastapi import FastAPI, UploadFile, File, Form

@app.post("/process")
async def process(
    payload_text: str = Form(None),
    file: UploadFile = File(None),
    mtu: int = Form(20),
    src_ip: str = Form("10.0.0.1"),
    dst_ip: str = Form("10.0.0.2"),
    transmission_type: "TransmissionType" = Form("unicast"),
    dst_list: str = Form("")
):
    # 1) Lee bytes del archivo (si viene)
    file_bytes = None
    if file is not None:
        file_bytes = await file.read()
        # (opcional) valida tamaño max aquí

    # 2) Capa de presentación -> payload en base64
    pres = presentation_layer(payload_text, file_bytes)

    # 3) Capa de transporte -> fragmentación por MTU
    transport_segments = transport_layer(pres, mtu)

    # 4) Resolver destinos según el tipo (usa tus helpers existentes)
    targets = resolve_targets(TransmissionType(transmission_type), dst_ip, dst_list)

    # 5) Capa de red por destino (usa tu wrapper que ya agregamos)
    packets_by_dst = network_layer_by_destination(
        transport_segments=transport_segments,
        src_ip=src_ip,
        dst_ips=targets,
        transmission_type=TransmissionType(transmission_type)
    )

    # 6) Persistencia en memoria (respeta tu estructura base)
    pid = str(uuid.uuid4())
    PROCESS_STORE[pid] = {
        "created_at": time.time(),
        "meta": {
            "src_ip": src_ip,
            "transmission_type": TransmissionType(transmission_type).value,
            "dst_ips": targets,
            "mtu": mtu,
        },
        "deliveries": {
            dst: {
                "fragments": packets_by_dst[dst],
                "transport_total": len(transport_segments),
                "reassembled": None
            }
            for dst in targets
        }
    }

    first_dst = targets[0]
    deliveries_summary = [
        {"dst_ip": d, "fragments": len(PROCESS_STORE[pid]["deliveries"][d]["fragments"])}
        for d in targets
    ]

    return {
        "pid": pid,
        "meta": PROCESS_STORE[pid]["meta"],
        "deliveries_summary": deliveries_summary,
        "fragments": PROCESS_STORE[pid]["deliveries"][first_dst]["fragments"]  # compat con tu UI actual
    }

@app.get("/health")
async def health():
	return JSONResponse({"status": "ok"})

# Nuevo endpoint: reensamblar fragments en destino
@app.post("/reassemble")
async def reassemble(pid: str = Form(...), dst_ip: str = Form(None)):
    """
    Reensambla por destino. Si no se envía dst_ip, usa el primero.
    """
    proc = PROCESS_STORE.get(pid)
    if not proc:
        return {"error": "not_found"}

    deliveries = proc.get("deliveries", {})
    if not deliveries:
        return {"error": "no_deliveries"}

    if not dst_ip:
        dst_ip = proc["meta"]["dst_ips"][0]

    if dst_ip not in deliveries:
        return {"error": "destination_not_found"}

    fragments = deliveries[dst_ip]["fragments"]

    # Usa tu lógica actual de reensamble (ordenar por transport_seq, validar total, etc.)
    # reassembled_bytes = ...
    # deliveries[dst_ip]["reassembled"] = reassembled_bytes

    return {
        "pid": pid,
        "dst_ip": dst_ip,
        "status": "ok",
        # Puedes devolver un hash/len del reensamble o el resultado según tu API actual
        # "size": len(reassembled_bytes)
    }

# Nuevo endpoint: descargar reensamblado como archivo (stream)
@app.post("/download")
async def download(payload: Dict[str, Any] = Body(...)):
	"""
	Recibe el mismo JSON que /reassemble y devuelve el contenido reensamblado como attachment.
	"""
	try:
		fragments = payload.get("fragments") or []
		if not isinstance(fragments, list) or len(fragments) == 0:
			return JSONResponse({"error": "no_fragments", "message": "No se recibieron fragments"}, status_code=400)

		# ordenar y concatenar como en reassemble
		try:
			fragments_sorted = sorted(fragments, key=lambda f: f.get("header", {}).get("transport_seq", 0))
		except Exception:
			fragments_sorted = fragments

		parts = []
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
		size = len(reassembled_bytes)

		if size == 0:
			return JSONResponse({"error": "empty_payload", "message": "El payload reensamblado está vacío"}, status_code=400)

		# Nombre y tipo
		filename = payload.get("filename") or "reassembled.bin"
		# Determinar content-type básico: si type == text -> text/plain; else octet-stream
		content_type = "application/octet-stream"
		if payload.get("type") == "text":
			content_type = "text/plain; charset=utf-8"

		# Preparar StreamingResponse desde bytes
		stream = io.BytesIO(reassembled_bytes)
		headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
		return StreamingResponse(stream, media_type=content_type, headers=headers)
	except Exception as e:
		return JSONResponse({"error": "internal_error", "message": str(e)}, status_code=500)

# Nuevo: obtener resultado por id
@app.get("/result/{pid}")
async def get_result(pid: str):
	item = PROCESS_STORE.get(pid)
	# comprobar existencia y expiración
	if not item:
		return JSONResponse({"error": "not_found", "message": "process_id no existe"}, status_code=404)
	if item.get("expires", 0) <= time.time():
		# eliminar y reportar expirado
		PROCESS_STORE.pop(pid, None)
		return JSONResponse({"error": "expired", "message": "process_id expirado"}, status_code=404)
	# devolver el objeto de respuesta almacenado (no exponer fragments completos si se desea)
	resp = item.get("response", {})
	# añadir metadatos
	resp_meta = {"process_id": pid, "created": item.get("created"), "expires": item.get("expires")}
	resp_meta.update(resp)
	return JSONResponse(resp_meta)

# Nuevo: descargar por id (GET)
@app.get("/download/{pid}")
async def download_by_id(pid: str):
	item = PROCESS_STORE.get(pid)
	# comprobar existencia y expiración
	if not item:
		return JSONResponse({"error": "not_found", "message": "process_id no existe"}, status_code=404)
	if item.get("expires", 0) <= time.time():
		PROCESS_STORE.pop(pid, None)
		return JSONResponse({"error": "expired", "message": "process_id expirado"}, status_code=404)
	fragments = item.get("fragments", []) or []
	# reconstruir bytes
	parts = []
	for f in fragments:
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
		return JSONResponse({"error": "empty_payload", "message": "El payload reensamblado está vacío"}, status_code=400)
	filename = item.get("filename") or "reassembled.bin"
	content_type = "application/octet-stream"
	if item.get("type") == "text":
		content_type = "text/plain; charset=utf-8"
	stream = io.BytesIO(reassembled_bytes)
	headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
	return StreamingResponse(stream, media_type=content_type, headers=headers)

# Background cleanup task: eliminar entries expiradas periódicamente
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
			# evitar que excepciones detengan el loop
			await asyncio.sleep(interval)

@app.on_event("startup")
async def start_cleanup_task():
	# iniciar tarea de limpieza en background
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