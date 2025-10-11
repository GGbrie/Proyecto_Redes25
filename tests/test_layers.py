import base64
import math
from fastapi.testclient import TestClient

# ...existing project import...
from main import app, presentation_layer, transport_layer

client = TestClient(app)

def test_presentation_text():
	pres = presentation_layer(text="Hola")
	assert pres["type"] == "text"
	assert "payload_b64" in pres
	decoded = base64.b64decode(pres["payload_b64"].encode("ascii"))
	assert decoded.decode("utf-8") == "Hola"

def test_transport_fragmentation_and_reassembly_integrity():
	# payload 120 bytes -> with mtu 50 should give 3 fragments
	payload = "A" * 120
	pres = presentation_layer(text=payload)
	tr = transport_layer(pres["payload_b64"], mtu=50)
	assert tr["total_len"] == 120
	expected_frags = math.ceil(120 / 50)
	assert len(tr["fragments"]) == expected_frags
	# re-concatenate fragments and compare with original bytes
	parts = b"".join([base64.b64decode(f["payload_b64"].encode("ascii")) for f in tr["fragments"]])
	orig = base64.b64decode(pres["payload_b64"].encode("ascii"))
	assert parts == orig

def test_reassemble_endpoint_text():
	# small mtu to force fragmentation
	pres = presentation_layer(text="Hello world")
	tr = transport_layer(pres["payload_b64"], mtu=5)
	fragments = tr["fragments"]
	resp = client.post("/reassemble", json={"fragments": fragments, "type": "text"})
	assert resp.status_code == 200
	j = resp.json()
	assert j["type"] == "text"
	assert j["text"] == "Hello world"

def test_reassemble_endpoint_binary():
	# binary payload (not valid utf-8) should return binary payload_b64
	data = bytes([0,1,2,3,4,255,254,253])
	encoded = base64.b64encode(data).decode("ascii")
	# craft fragments: single fragment
	fragments = [{"header": {"transport_seq": 1, "transport_total": 1, "transport_len": len(data)}, "payload_b64": encoded}]
	resp = client.post("/reassemble", json={"fragments": fragments, "type": "image", "filename": "bin.bin"})
	assert resp.status_code == 200
	j = resp.json()
	assert j["type"] in ("image", "binary")
	assert "payload_b64" in j
	decoded = base64.b64decode(j["payload_b64"].encode("ascii"))
	assert decoded == data
