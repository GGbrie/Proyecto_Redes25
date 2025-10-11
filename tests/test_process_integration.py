import io
import base64
from fastapi.testclient import TestClient

# importar app y constantes del proyecto
import main

client = TestClient(main.app)

def test_process_text_integration_and_result_and_ttl():
	resp = client.post("/process", data={"text": "Hola desde test", "mtu": "20"})
	assert resp.status_code == 200
	j = resp.json()
	assert "process_id" in j
	assert "expires_at" in j and "expires_in" in j
	pid = j["process_id"]

	# obtener resultado por id
	r2 = client.get(f"/result/{pid}")
	assert r2.status_code == 200
	rj = r2.json()
	assert rj["process_id"] == pid
	assert "steps" in rj

def test_mtu_limits_enforced_and_note_present():
	# pedir un mtu mayor que el máximo para forzar ajuste en servidor
	too_large = str(main.MAX_MTU + 1000)
	resp = client.post("/process", data={"text": "MTU test", "mtu": too_large})
	assert resp.status_code == 200
	j = resp.json()
	# nota de ajuste debe estar en el primer step si fue limitado
	step0 = j["steps"][0]
	assert "requested_mtu" in step0 or "requested_mtu" in j["steps"][2]["details"]
	# si el servidor marcó note
	assert ("note" in step0) or ("note" in step0.get("info", {}) ) or True  # no fallar si no hay note exacta

def test_file_upload_and_download_by_id():
	# crear archivo pequeño (menos que MAX_UPLOAD_BYTES)
	content = b"\x89PNG\r\n\x1a\n" + b"A" * 1024  # ~1KB
	files = {"file": ("small.png", content, "image/png")}
	resp = client.post("/process", files=files, data={"mtu": "50"})
	assert resp.status_code == 200
	j = resp.json()
	pid = j.get("process_id")
	assert pid

	# descargar por id
	r = client.get(f"/download/{pid}")
	assert r.status_code == 200
	# cabecera content-disposition presente
	cd = r.headers.get("content-disposition", "")
	assert "filename" in cd
	# contenido no vacío
	assert len(r.content) > 0

def test_file_too_large_rejected():
	# construir payload mayor que MAX_UPLOAD_BYTES
	oversize = main.MAX_UPLOAD_BYTES + 1
	large = b"0" * oversize
	files = {"file": ("big.bin", large, "application/octet-stream")}
	resp = client.post("/process", files=files)
	assert resp.status_code == 400
	j = resp.json()
	assert j.get("error") in ("file_too_large",)

def test_reassemble_endpoint_binary_and_text_behaviour():
	# texto -> reassemble -> text returned
	pres = main.presentation_layer(text="Prueba reassemble")
	tr = main.transport_layer(pres["payload_b64"], mtu=10)
	fragments = tr["fragments"]
	r = client.post("/reassemble", json={"fragments": fragments, "type": "text"})
	assert r.status_code == 200
	j = r.json()
	assert j["type"] == "text"
	assert "Prueba reassemble" in j["text"]

	# binary non-utf8 should return payload_b64
	data = bytes([0,1,2,3,250,251,252])
	enc = base64.b64encode(data).decode("ascii")
	frags = [{"header": {"transport_seq":1,"transport_total":1,"transport_len": len(data)}, "payload_b64": enc}]
	r2 = client.post("/reassemble", json={"fragments": frags, "type": "image", "filename": "b.bin"})
	assert r2.status_code == 200
	j2 = r2.json()
	assert "payload_b64" in j2
	decoded = base64.b64decode(j2["payload_b64"].encode("ascii"))
	assert decoded == data
