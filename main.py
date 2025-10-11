import os
from fastapi import FastAPI, Request, UploadFile, File, Form
from fastapi.responses import JSONResponse, HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import base64
import math
import io
from typing import List, Dict, Any
from fastapi import Body
import uuid
import time
import asyncio

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

def presentation_layer(text: str = None, file_bytes: bytes = None, file_name: str = None):
	# Devuelve dict con tipo, raw_bytes y encoded (base64 str) y info de codificación
	if file_bytes is not None:
		encoded = base64.b64encode(file_bytes).decode('ascii')
		return {
			"type": "image",
			"filename": file_name,
			"raw_bytes_len": len(file_bytes),
			"encoding": "base64",
			"payload_b64": encoded
		}
	else:
		raw = text.encode('utf-8')
		encoded = base64.b64encode(raw).decode('ascii')
		return {
			"type": "text",
			"raw_text": text,
			"raw_bytes_len": len(raw),
			"encoding": "utf-8 + base64",
			"payload_b64": encoded
		}

def transport_layer(payload_b64: str, mtu: int = 50):
	# Simula fragmentación; mtu en bytes del payload (usamos len of decoded bytes)
	payload_bytes = base64.b64decode(payload_b64.encode('ascii'))
	total_len = len(payload_bytes)
	# Siempre devolver las keys esperadas para evitar KeyError en el consumidor
	if total_len == 0:
		return {"fragments": [], "mtu": mtu, "total_len": total_len}
	num_frag = math.ceil(total_len / mtu)
	fragments = []
	for i in range(num_frag):
		start = i * mtu
		end = start + mtu
		part = payload_bytes[start:end]
		part_b64 = base64.b64encode(part).decode('ascii')
		header = {
			"transport_seq": i + 1,
			"transport_total": num_frag,
			"transport_len": len(part)
		}
		fragments.append({"header": header, "payload_b64": part_b64})
	return {"fragments": fragments, "mtu": mtu, "total_len": total_len}

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

@app.post("/process")
async def process(text: str = Form(None), file: UploadFile = File(None), mtu: int = Form(50)):
	# Manejo seguro para que siempre devolvamos JSON aunque algo falle
	try:
		# Interfaz de Usuario (capa aplicación)
		# Nota: no considerar 'file' como presente si filename es vacío o contenido 0 bytes
		has_file = False
		file_content = None
		file_name = None
		if file and getattr(file, "filename", ""):
			# leer contenido, puede ser grande; este ejemplo lo lee entero
			content = await file.read()
			# validar tamaño en servidor
			if content and len(content) > 0:
				if len(content) > MAX_UPLOAD_BYTES:
					return JSONResponse({"error": "file_too_large", "message": f"Archivo supera el límite de {MAX_UPLOAD_BYTES} bytes"}, status_code=400)
				has_file = True
				file_content = content
				file_name = file.filename

		# Validar texto tamaño (si se envía texto muy grande)
		if text:
			raw_bytes = text.encode('utf-8')
			if len(raw_bytes) > MAX_UPLOAD_BYTES:
				return JSONResponse({"error": "text_too_large", "message": f"Texto supera el límite de {MAX_UPLOAD_BYTES} bytes"}, status_code=400)

		if not text and not has_file:
			return JSONResponse({"error": "Enviar 'text' o 'file'."}, status_code=400)

		# Validar mtu recibido (si viene mal, usar 50) y limitar rango
		try:
			mtu = int(mtu)
		except Exception:
			mtu = 50
		limited_mtu = False
		if mtu < MIN_MTU:
			mtu = MIN_MTU
			limited_mtu = True
		if mtu > MAX_MTU:
			mtu = MAX_MTU
			limited_mtu = True

		ui_step = {"layer": "Application (Interfaz de Usuario)", "info": "Entrada recibida", "has_text": bool(text), "has_file": has_file, "requested_mtu": mtu}
		if limited_mtu:
			ui_step["note"] = f"mtu adjusted to range [{MIN_MTU},{MAX_MTU}]"

		# Presentación / Codificador
		if has_file:
			pres = presentation_layer(text=None, file_bytes=file_content, file_name=file_name)
		else:
			pres = presentation_layer(text=text, file_bytes=None, file_name=None)

		# Transporte (usar mtu proporcionado)
		tr = transport_layer(pres["payload_b64"], mtu=mtu)

		# Red
		net_frags = network_layer(tr.get("fragments", []))

		# Física (simulación)
		phys_logs = physical_layer_simulation(net_frags)

		# Construir respuesta con pasos (indicar mtu usado)
		response = {
			"limits": {"max_upload_bytes": MAX_UPLOAD_BYTES, "min_mtu": MIN_MTU, "max_mtu": MAX_MTU},
			"steps": [
				ui_step,
				{"layer": "Presentation (Codificador)", "details": {k: v for k, v in pres.items() if k != "payload_b64"}},
				{"layer": "Transport", "details": {"requested_mtu": mtu, "mtu": tr.get("mtu", mtu), "total_len": tr.get("total_len", 0), "fragments_count": len(tr.get("fragments", [])), "fragments": tr.get("fragments", [])}},
				{"layer": "Network", "details": {"fragments_with_network_header": net_frags}},
				{"layer": "Physical (Transmisión Visual)", "details": {"logs": phys_logs}}
			]
		}

		# Generar process_id y almacenar datos relevantes (no almacenar payload base64 completo si no es necesario)
		pid = uuid.uuid4().hex
		now = time.time()
		expires_at = now + PROCESS_TTL_SECONDS
		PROCESS_STORE[pid] = {
			"created": now,
			"expires": expires_at,
			"response": response,
			"fragments": tr.get("fragments", []),
			"type": pres.get("type"),
			"filename": pres.get("filename")
		}
		# Incluir id y expiración en la respuesta devuelta al cliente
		response["process_id"] = pid
		response["expires_at"] = expires_at
		response["expires_in"] = PROCESS_TTL_SECONDS

		return JSONResponse(response)
	except Exception as e:
		# Devolver JSON con mensaje de error (no exponer stacktrace en producción)
		return JSONResponse({"error": "internal_error", "message": str(e)}, status_code=500)

# Endpoint de comprobación rápido
@app.get("/health")
async def health():
	return JSONResponse({"status": "ok"})

# Nuevo endpoint: reensamblar fragments en destino
@app.post("/reassemble")
async def reassemble(payload: Dict[str, Any] = Body(...)):
	"""
	Espera JSON:
	{ "fragments": [ { "header": {...}, "payload_b64": "..." }, ... ],
	  "type": "text"|"image" (opcional),
	  "filename": "imagen.png" (opcional)
	}
	Devuelve JSON con el contenido reensamblado.
	"""
	try:
		fragments = payload.get("fragments") or []
		if not isinstance(fragments, list) or len(fragments) == 0:
			return JSONResponse({"error": "no_fragments", "message": "No se recibieron fragments"}, status_code=400)

		# Ordenar por transport_seq (si falta, mantener orden)
		try:
			fragments_sorted = sorted(fragments, key=lambda f: f.get("header", {}).get("transport_seq", 0))
		except Exception:
			fragments_sorted = fragments

		# Concatenar bytes de cada fragment (decodificando base64)
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

		# Determinar tipo
		content_type = payload.get("type")
		filename = payload.get("filename")

		# Si se indica o se detecta texto, intentar decodificar UTF-8
		if content_type == "text" or (content_type is None):
			try:
				text = reassembled_bytes.decode("utf-8")
				return JSONResponse({"type": "text", "text": text, "size": size})
			except Exception:
				encoded = base64.b64encode(reassembled_bytes).decode("ascii")
				return JSONResponse({"type": "binary", "payload_b64": encoded, "size": size, "note": "no utf-8"})

		# Si es imagen u otro binario, devolver base64 y filename si existe
		encoded = base64.b64encode(reassembled_bytes).decode("ascii")
		resp = {"type": "image", "payload_b64": encoded, "size": size}
		if filename:
			resp["filename"] = filename
		return JSONResponse(resp)
	except Exception as e:
		return JSONResponse({"error": "internal_error", "message": str(e)}, status_code=500)

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