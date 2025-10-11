Proyecto: Simulador de Protocolo (FastAPI + simple frontend)

Requisitos
- Python 3.8+
- Crear virtualenv recomendado

Instalación
1) python -m venv .venv
2) Windows: .venv\Scripts\activate
3) pip install -r requirements.txt

Ejecutar
- uvicorn main:app --reload --port 8000
- Abrir http://127.0.0.1:8000

Endpoints principales
- GET /           -> UI (templates/index.html)
- POST /process   -> procesa texto/imagen y muestra pasos (presentación, transporte, red, física). Devuelve process_id.
- POST /reassemble-> reensambla fragments (JSON) y devuelve contenido (JSON)
- POST /download  -> reensambla fragments y devuelve archivo como attachment
- GET /result/{id} -> obtiene resultado almacenado por process_id
- GET /download/{id} -> descarga archivo reensamblado por process_id
- GET /health     -> health check

Retención (TTL)
- Los resultados generados por /process se almacenan temporalmente en memoria con un TTL por defecto:
  PROCESS_TTL_SECONDS = 3600 (1 hora).
- Las entradas expiradas se limpian periódicamente por una tarea en background.
- Si intentas acceder a /result/{id} o /download/{id} después de la expiración, recibirás un error "expired".

Límites por defecto
- Tamaño máximo de subida: 5 MB (MAX_UPLOAD_BYTES = 5*1024*1024)
- MTU permitido: entre 1 y 65535 (MIN_MTU / MAX_MTU)

Notas
- El frontend valida el tamaño antes de enviar y ajusta MTU. El servidor también valida y rechazará cargas que excedan MAX_UPLOAD_BYTES.
- Ajusta MAX_UPLOAD_BYTES, MIN_MTU, MAX_MTU y PROCESS_TTL_SECONDS en main.py si necesitas otros límites o retención.
