import os       # Para variables de entorno (TTL)
import io       # Para manejo de bytes en memoria (para descargas)
import time     # Para marcas de tiempo y expiración
import base64   # Para codificar/decodificar en Base64
import asyncio  # Para tareas asíncronas (limpieza)
import uuid     # Para generar IDs únicos
from typing import Optional, List, Dict, Any # Tipado estático de Python

# Importaciones de FastAPI
from fastapi import FastAPI, Request, UploadFile, File, Form, HTTPException, Body
from fastapi.responses import JSONResponse, HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

# =========================
# Configuración y constantes
# =========================
MAX_UPLOAD_BYTES = 50 * 1024 * 1024 # Límite de subida (50 MB)
MIN_MTU = 1
MAX_MTU = 65535
# Tiempo de vida (TTL) de un proceso en segundos (10 minutos por defecto)
PROCESS_TTL_SECONDS = int(os.getenv("PROCESS_TTL_SECONDS", str(10 * 60)))  

# Tabla ARP simulada (mapeo de IP a MAC)
MAC_TABLE = {
    "10.0.0.1": "0A:00:00:01",
    "10.0.0.2": "0A:00:00:02",
    "default": "0A:FF:FF:01", # MAC por defecto si no se encuentra la IP
}
BROADCAST_MAC = "FF:FF:FF:FF:FF:FF" # Dirección MAC de Broadcast
BROADCAST_IPS = ["255.255.255.255", "10.0.0.255"] # IPs de Broadcast

# =========================
# App y templates
# =========================
app = FastAPI() # Instancia principal de la aplicación FastAPI

# Monta la carpeta 'static' si existe (para CSS, JS, imágenes estáticas)
if os.path.isdir("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")
# Configura el motor de plantillas Jinja2 para buscar HTML en la carpeta 'templates'
templates = Jinja2Templates(directory="templates") 

# Almacén en memoria: Un diccionario que guardará todos los procesos
# La clave es el 'pid' (process_id)
PROCESS_STORE: Dict[str, Dict[str, Any]] = {}

# ==========================================
# LÓGICA DE CAPAS (Simulación OSI)
# ==========================================

def presentation_layer(payload_text: Optional[str], file_bytes: Optional[bytes]) -> dict:
    """
    (Capa 6 - Presentación)
    Toma el input (texto o archivo) y lo convierte a un formato estándar (Base64).
    """
    if payload_text and payload_text.strip():
        # Si hay texto, lo codifica en UTF-8
        raw = payload_text.encode("utf-8")
        ctype = "text/plain; charset=utf-8"
    elif file_bytes:
        # Si hay un archivo, usa los bytes crudos
        raw = file_bytes
        ctype = "application/octet-stream" # Tipo genérico para binarios
    else:
        # Si no hay nada, lanza un error
        raise HTTPException(status_code=400, detail="Payload vacío")

    # Codifica los bytes crudos a Base64 (formato de texto seguro)
    payload_b64 = base64.b64encode(raw).decode("ascii")
    return {
        "content_type": ctype, # Tipo de contenido original
        "size": len(raw),      # Tamaño original en bytes
        "payload_b64": payload_b64, # Payload codificado
    }


def transport_layer(pres: dict, mtu: int) -> List[dict]:
    """
    (Capa 4 - Transporte)
    Fragmenta el payload (de Capa 6) en segmentos más pequeños según el MTU.
    """
    if mtu is None or mtu <= 0:
        mtu = MIN_MTU
    # Asegura que el MTU esté dentro de los límites válidos
    mtu = max(MIN_MTU, min(int(mtu), MAX_MTU))

    payload_b64: str = pres["payload_b64"]
    # Decodifica el Base64 de vuelta a bytes para poder fragmentarlo
    payload_bytes = base64.b64decode(payload_b64.encode("ascii"))
    
    # Divide los bytes en trozos (chunks) del tamaño del MTU
    chunks = [payload_bytes[i:i + mtu] for i in range(0, len(payload_bytes), mtu)]
    if not payload_bytes:
        chunks = [b""] # Asegura que haya al menos un segmento (vacío) si el payload estaba vacío
    total = len(chunks) # Número total de segmentos

    segments: List[dict] = []
    # Itera sobre cada trozo y le añade una cabecera de transporte simulada
    for i, ch in enumerate(chunks, start=1):
        segments.append({
            "transport_header": {
                "seq": i,       # Número de secuencia
                "total": total, # Total de segmentos
                "mtu": mtu,
            },
            # Vuelve a codificar el trozo (chunk) en Base64
            "payload_b64": base64.b64encode(ch).decode("ascii"),
        })
    return segments


def network_layer_by_destination(
    transport_segments: List[dict],
    src_ip: str,
    dst_ips: List[str], # Puede enviar a múltiples destinos (aunque la UI solo usa 1)
) -> Dict[str, List[dict]]:
    """
    (Capa 3 - Red)
    Toma los segmentos (de Capa 4) y los envuelve en paquetes, añadiendo cabeceras IP.
    """
    packets_by_dst: Dict[str, List[dict]] = {}
    for dst in dst_ips:
        packets = []
        # Itera sobre cada segmento y le añade una cabecera de red
        for seg in transport_segments:
            net_header = {
                "src_ip": src_ip,
                "dst_ip": dst,
                "protocol": "SIMPROTO/1.0", # Protocolo simulado
                "ttl": 64, # Tiempo de vida (Time To Live)
            }
            packets.append({
                "network_header": net_header,
                **seg, # Copia el contenido del segmento (cabecera de transporte + payload)
            })
        packets_by_dst[dst] = packets
    return packets_by_dst


def data_link_layer(
    packets_by_dst: Dict[str, List[dict]]
) -> Dict[str, List[dict]]:
    """
    (Capa 2 - Enlace de Datos)
    Toma los paquetes (de Capa 3) y los envuelve en tramas, añadiendo cabeceras MAC.
    """
    frames_by_dst: Dict[str, List[dict]] = {}
    
    for dst_ip, packets in packets_by_dst.items():
        frames = []
        # Busca la MAC de origen en la tabla ARP simulada
        src_mac = MAC_TABLE.get(packets[0]["network_header"]["src_ip"], MAC_TABLE["default"])
        
        for p in packets:
            transmission_type = "Unicast" # Por defecto, es Unicast
            # Comprueba si la IP de destino es de Broadcast
            if dst_ip in BROADCAST_IPS:
                dst_mac = BROADCAST_MAC
                transmission_type = "Broadcast"
            else:
                # Si no, busca la MAC de destino en la tabla ARP
                dst_mac = MAC_TABLE.get(dst_ip, MAC_TABLE["default"])
            
            # Añade la cabecera de enlace (MAC)
            link_header = {
                "src_mac": src_mac,
                "dst_mac": dst_mac,
                "type": "SIMv4", # Tipo de trama simulado
                "transmission_type": transmission_type 
            }
            frames.append({
                "data_link_header": link_header,
                **p, # Copia el contenido del paquete (cabecera red + cabecera transporte + payload)
            })
        frames_by_dst[dst_ip] = frames
        
    return frames_by_dst

# ==========================================
# LÓGICA (Generación de Resumen y Pasos)
# ==========================================
def build_summary(
    pres: dict, 
    transport_segments: list, 
    packets_by_dst: dict, 
    frames_by_dst: dict,
    mtu: int
) -> dict:
    """
    Construye un diccionario de resumen con toda la información de la simulación.
    Este resumen se usa en el frontend para mostrar los detalles.
    """
    
    # Cálculos estadísticos
    total_raw_len = pres.get("size", 0)
    frag_count = len(transport_segments)
    net_packets = sum(len(v) for v in packets_by_dst.values())
    link_frames = sum(len(v) for v in frames_by_dst.values())
    
    # Obtiene información de la primera trama/paquete para el resumen
    first_frame = {}
    if link_frames > 0:
        first_dst_ip = list(frames_by_dst.keys())[0]
        first_frame = frames_by_dst[first_dst_ip][0].get("data_link_header", {})
    
    first_packet = {}
    if net_packets > 0:
        first_dst_ip = list(packets_by_dst.keys())[0]
        first_packet = packets_by_dst[first_dst_ip][0].get("network_header", {})

    # Diccionario de resumen estructurado por capas
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
            "fragments_info": [ # Lista de información de cada segmento
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
        
        # --- Computadora Destino (info para el resumen) ---
        "Receiver": {
            "dst_ip": first_packet.get("dst_ip", "N/A"),
            "dst_mac": first_frame.get("dst_mac", "N/A")
        }
    }


def build_encapsulation_steps(summary: dict) -> List[dict]:
    """Genera los pasos de ENVÍO (Capas 7 a 1) para el carrusel."""
    src_ip = summary["Network"]["src_ip"]
    return [
        {"title": f"ENVÍO (Origen: {src_ip})", "detail": "Inicio del proceso de encapsulación..."},
        {"title": "Capa No.7: Aplicación para la Interfaz del Usuario:", 
         "detail": summary["Application"]["ui"]},
        {"title": "Capa No.6: Presentación -- Codificador:", 
         "detail": f"Tipo: {summary['Presentation']['type']}\nTamaño: {summary['Presentation']['raw_bytes_len']} bytes\nCodificación: {summary['Presentation']['encoding']}"},
        {"title": "Capa No.5: Sesión -- Control:",
         "detail": summary["Session"]["info"]},
        {"title": "Capa No.4: Trasporte -- Segmentación:", 
         "detail": f"Encabezado de Transporte añadido:\nMTU: {summary['Transport']['requested_mtu']} bytes\nSegmentos: {summary['Transport']['fragments_count']}\n" + "\n".join(summary['Transport']['fragments_info'])},
        {"title": "Capa No.3: Red -- Paquetes:", 
         "detail": f"Encabezado de Red añadido:\nProtocolo: {summary['Network']['protocol']}\nPaquetes: {summary['Network']['total_packets']}\nIP Origen: {summary['Network']['src_ip']}\nIP Destino: {summary['Network']['dst_ip']}"},
        {"title": "Capa No.2: Enlace de Datos -- Tramas:", 
         "detail": f"Encabezado de Enlace añadido:\nTramas: {summary['DataLink']['total_frames']}\nTipo: {summary['DataLink']['transmission_type']}\nMAC Origen: {summary['DataLink']['src_mac']}\nMAC Destino: {summary['DataLink']['dst_mac']}"},
        {"title": "Capa No.1: Física -- Transmisión:", 
         "detail": summary["Physical"]["logs"][0]},
    ]

def build_decapsulation_steps(summary: dict) -> List[dict]:
    """Genera los pasos de RECEPCIÓN (Capas 1 a 7) para el carrusel."""
    dst_ip = summary["Receiver"]["dst_ip"]
    dst_mac = summary["Receiver"]["dst_mac"]
    
    return [
        {"title": f"RECEPCIÓN (Destino: {dst_ip})", "detail": "Inicio del proceso de desencapsulación..."},
        {"title": "Capa No.1: Física -- Recepción:", 
         "detail": f"Se reciben bits del medio y se agrupan para formar tramas."},
        {"title": "Capa No.2: Enlace de Datos -- Desencapsulado:", 
         "detail": f"Se lee el encabezado de Enlace.\n¿Es esta MAC para mí? ({dst_mac}) -> SÍ.\nSe quita el encabezado de enlace y se pasa el paquete a la Capa 3."},
        {"title": "Capa No.3: Red -- Desencapsulado:", 
         "detail": f"Se lee el encabezado de Red.\n¿Es esta IP para mí? ({dst_ip}) -> SÍ.\nSe quita el encabezado de red y se pasa el segmento a la Capa 4."},
        {"title": "Capa No.4: Trasporte -- Reensamblado:", 
         "detail": f"Se leen los encabezados de Transporte (seq 1, 2, 3...).\nSe reensamblan los {summary['Transport']['fragments_count']} segmentos en orden.\nSe entrega el bloque de datos a la Capa 5."},
        {"title": "Capa No.5: Sesión -- Control:",
         "detail": "Se gestiona la sesión (se confirma la recepción de datos)."},
        {"title": "Capa No.6: Presentación -- Decodificador:", 
         "detail": f"Se decodifican los datos (Base64 -> {summary['Presentation']['type']})\nDatos listos para la aplicación."},
        {"title": "Capa No.7: Entrega de la Aplicación:", 
         "detail": "Los datos reensamblados y decodificados se entregan a la aplicación final."},
    ]


# =========================
# Rutas (Endpoints API)
# =========================

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Sirve la página principal (origen.html)"""
    try:
        # Intenta renderizar la plantilla 'origen.html'
        return templates.TemplateResponse("origen.html", {"request": request})
    except Exception:
        # Si falla (ej: archivo no encontrado), devuelve un HTML de error
        html = """
        <html><body>
        <h2>Simulador de Protocolo - Origen</h2>
        <p>Error: No se encontró 'templates/origen.html'. Asegúrate de que el archivo existe en la carpeta 'templates'.</p>
        </body></html>
        """
        return HTMLResponse(html, status_code=500)
    
@app.get("/destino", response_class=HTMLResponse)
async def get_destino(request: Request):
    """Sirve la página de destino (destino.html)"""
    try:
        return templates.TemplateResponse("destino.html", {"request": request})
    except Exception:
        html = """
        <html><body>
        <h2>Simulador de Protocolo - Destino</h2>
        <p>Error: No se encontró 'templates/destino.html'. Asegúrate de que el archivo existe en la carpeta 'templates'.</p>
        </body></html>
        """
        return HTMLResponse(html, status_code=500)


@app.get("/health")
async def health():
    """Endpoint simple para verificar que el servidor está vivo."""
    return {"status": "ok"}


@app.post("/process")
async def process(
    # Lee los datos del formulario (multipart/form-data)
    payload_text: Optional[str] = Form(None),
    text: Optional[str] = Form(None), # Campo 'text' como alternativa para 'payload_text'
    file: UploadFile = File(None),    # Archivo subido
    mtu: int = Form(50),              # MTU
    src_ip: str = Form("10.0.0.1"),   # IP Origen
    dst_ip: str = Form("10.0.0.2"),   # IP Destino
):
    """
    Endpoint principal. Recibe los datos, simula la encapsulación
    y almacena el resultado en memoria.
    """
    # Combina 'payload_text' y 'text' por si se envía con uno u otro nombre
    payload_text = payload_text if (payload_text and payload_text.strip()) else (
        text if (text and text.strip()) else None
    )

    file_bytes = None
    if file is not None:
        file_bytes = await file.read() # Lee los bytes del archivo
        # Validación de tamaño
        if file_bytes and len(file_bytes) > MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail=f"Archivo demasiado grande ({len(file_bytes) // 1024} KB). Límite: {MAX_UPLOAD_BYTES // 1024} KB")

    # --- SIMULACIÓN DE ENCAPSULACIÓN (Llamada a las funciones de capa) ---
    pres = presentation_layer(payload_text, file_bytes)           # Capa 6
    transport_segments = transport_layer(pres, mtu)               # Capa 4
    targets = [dst_ip or "10.0.0.2"]
    packets_by_dst = network_layer_by_destination(                # Capa 3
        transport_segments=transport_segments,
        src_ip=src_ip,
        dst_ips=targets,
    )
    frames_by_dst = data_link_layer(packets_by_dst)               # Capa 2
    
    # --- Creación y almacenamiento del proceso ---
    created = time.time() # Hora de creación
    expires = created + PROCESS_TTL_SECONDS # Hora de expiración
    
    # Construye el resumen y los pasos
    summary = build_summary(pres, transport_segments, packets_by_dst, frames_by_dst, mtu)
    encapsulation_steps = build_encapsulation_steps(summary)
    decapsulation_steps = build_decapsulation_steps(summary)
    steps = encapsulation_steps + decapsulation_steps

    # Genera un ID de proceso único (8 caracteres)
    pid = str(uuid.uuid4())[:8]
    # Almacena todo en el diccionario global 'PROCESS_STORE'
    PROCESS_STORE[pid] = {
        "created": created,
        "expires": expires,
        "meta": { # Metadatos de la solicitud
            "src_ip": src_ip,
            "dst_ips": targets,
            "mtu": mtu,
        },
        "deliveries": { # Datos "enviados" a cada destino
            dst: {
                "frames": frames_by_dst[dst], # Lista de todas las tramas
                "transport_total": len(transport_segments),
                "reassembled": None, # Espacio para el resultado reensamblado
            }
            for dst in targets
        },
        "summary": summary, # El resumen
        "steps": steps,     # Todos los pasos (encapsulación + desencapsulación)
    }

    # Prepara la respuesta para el frontend
    deliveries_summary = [
        {"dst_ip": d, "fragments": len(PROCESS_STORE[pid]["deliveries"][d]["frames"])}
        for d in targets
    ]
    first_dst = targets[0]

    # Devuelve la respuesta JSON a origen.html
    return {
        "pid": pid, # El ID de proceso
        "meta": PROCESS_STORE[pid]["meta"],
        "deliveries_summary": deliveries_summary,
        "fragments": PROCESS_STORE[pid]["deliveries"][first_dst]["frames"], # Las tramas (para descargas futuras)
        "summary": summary, # El resumen
        "steps": steps,     # Los pasos
        "expires_in": max(0, int(expires - time.time())), # Segundos restantes
    }

@app.post("/reassemble")
async def reassemble(pid: str = Form(None), dst_ip: str = Form(None)):
    """
    Endpoint (actualmente no usado por la UI) para forzar el reensamblado en el servidor.
    """
    if not pid:
        raise HTTPException(status_code=400, detail={"error": "missing_pid", "message": "pid es requerido"})

    proc = PROCESS_STORE.get(pid)
    if not proc:
        raise HTTPException(status_code=404, detail={"error": "not_found", "message": "process_id no existe"})

    # Validación de expiración
    if proc.get("expires", 0) <= time.time():
        PROCESS_STORE.pop(pid, None) # Limpia si está expirado
        raise HTTPException(status_code=404, detail={"error": "expired", "message": "process_id expirado"})

    deliveries = proc.get("deliveries", {})
    if not deliveries:
        raise HTTPException(status_code=400, detail={"error": "no_deliveries", "message": "No hay entregas para este proceso"})

    if not dst_ip:
        dst_ip = proc["meta"]["dst_ips"][0] # Usa el primer destino si no se especifica

    if dst_ip not in deliveries:
        raise HTTPException(status_code=404, detail={"error": "destination_not_found", "message": "Destino no encontrado"})

    frames = deliveries[dst_ip].get("frames", [])

    # Ordena las tramas por el número de secuencia (seq) de la cabecera de transporte
    try:
        frames_sorted = sorted(
            frames,
            key=lambda f: f.get("transport_header", {}).get("seq", 0)
        )
    except Exception:
        frames_sorted = frames # Si falla el ordenamiento, usa el orden original

    # Reensamblado: decodifica el Base64 de cada trama y junta los bytes
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

    reassembled_bytes = b"".join(parts) # Junta todos los trozos de bytes
    
    # Guarda el resultado en el almacén
    deliveries[dst_ip]["reassembled"] = reassembled_bytes

    return {"pid": pid, "dst_ip": dst_ip, "status": "ok", "size": len(reassembled_bytes)}


@app.post("/download")
async def download(payload: Dict[str, Any] = Body(None)):
    """
    Endpoint (actualmente no usado por la UI) que recibe un JSON con tramas
    y devuelve el archivo reensamblado.
    """
    if not payload or not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail={"error": "invalid_payload", "message": "Se requiere un JSON en el cuerpo"})

    frames = payload.get("frames") or payload.get("fragments") or []
    
    if not isinstance(frames, list) or len(frames) == 0:
        raise HTTPException(status_code=400, detail={"error": "no_fragments", "message": "No se recibieron frames/fragments"})

    # Ordena y reensambla (lógica idéntica a /reassemble)
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

    # Prepara la respuesta de descarga
    filename = payload.get("filename") or "reassembled.bin"
    content_type = "text/plain; charset=utf-8" if payload.get("type") == "text" else "application/octet-stream"

    stream = io.BytesIO(reassembled_bytes) # Crea un stream en memoria
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    # Devuelve una StreamingResponse que el navegador interpretará como una descarga
    return StreamingResponse(stream, media_type=content_type, headers=headers)


@app.get("/result/{pid}")
async def get_result(pid: str):
    """
    Endpoint usado por destino.html.
    Busca un proceso por su PID y devuelve toda la información almacenada.
    """
    item = PROCESS_STORE.get(pid)
    if not item:
        # Error si el PID no existe
        raise HTTPException(status_code=404, detail={"error": "not_found", "message": "process_id no existe"})
    
    # Validación de expiración
    if item.get("expires", 0) <= time.time():
        PROCESS_STORE.pop(pid, None) # Limpia el proceso expirado
        raise HTTPException(status_code=404, detail={"error": "expired", "message": "process_id expirado"})

    # Prepara la respuesta (similar a la de /process pero sin los fragmentos completos)
    targets = item["meta"]["dst_ips"]
    deliveries_summary = [
        {"dst_ip": d, "fragments": len(item["deliveries"][d]["frames"])}
        for d in targets
    ]
    first_dst = targets[0]

    # Devuelve el objeto completo del proceso
    return {
        "pid": pid,
        "meta": item["meta"],
        "deliveries_summary": deliveries_summary,
        # Devuelve solo los fragmentos del primer destino (la UI no los usa aquí)
        "fragments": item["deliveries"][first_dst]["frames"], 
        "summary": item.get("summary"),
        "steps": item.get("steps"),
        "expires_in": max(0, int(item["expires"] - time.time())),
        "created": item["created"],
        "expires": item["expires"],
    }


@app.get("/download/{pid}")
async def download_by_id(pid: str, dst_ip: Optional[str] = None):
    """
    Endpoint (actualmente no usado por la UI) para descargar el resultado
    reensamblado de un PID específico.
    """
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

    # Reensambla las tramas (lógica idéntica a /reassemble)
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

    # Prepara la respuesta de descarga
    content_type = "application/octet-stream"
    filename = f"reassembled_{dst_ip}.bin"

    stream = io.BytesIO(reassembled_bytes)
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    return StreamingResponse(stream, media_type=content_type, headers=headers)

# =========================
# Tareas de Fondo
# =========================

async def _cleanup_expired_processes(interval: int = 60):
    """
    Tarea asíncrona que se ejecuta en segundo plano para limpiar
    procesos expirados del almacén en memoria (PROCESS_STORE).
    """
    while True:
        try:
            now = time.time()
            # Encuentra todos los PIDs cuya hora de expiración es menor o igual a la actual
            expired = [pid for pid, item in PROCESS_STORE.items() if item.get("expires", 0) <= now]
            # Elimina cada PID expirado
            for pid in expired:
                PROCESS_STORE.pop(pid, None)
            # Espera el intervalo (60 segundos) antes de volver a revisar
            await asyncio.sleep(interval)
        except asyncio.CancelledError:
            break # Termina el bucle si la tarea se cancela (al apagar el servidor)
        except Exception:
            # Si ocurre un error, solo espera y vuelve a intentarlo
            await asyncio.sleep(interval)

@app.on_event("startup")
async def start_cleanup_task():
    """Se ejecuta cuando FastAPI inicia. Inicia la tarea de limpieza."""
    app.state._process_cleanup_task = asyncio.create_task(_cleanup_expired_processes(60))

@app.on_event("shutdown")
async def stop_cleanup_task():
    """Se ejecuta cuando FastAPI se apaga. Cancela la tarea de limpieza."""
    task = getattr(app.state, "_process_cleanup_task", None)
    if task:
        task.cancel()
        try:
            await task
        except Exception:
            pass