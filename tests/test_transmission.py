# tests/test_transmission.py
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def _process(**kwargs):
    # Helper para no repetir
    data = {
        "payload_text": "hola redes",
        "mtu": 4,
        "src_ip": "10.0.0.1",
        # dst_ip solo aplica a unicast; en broadcast lo ignoramos,
        # en multicast usamos dst_list.
    }
    data.update(kwargs)
    r = client.post("/process", data=data)
    assert r.status_code == 200, r.text
    return r.json()

def test_unicast_process():
    j = _process(transmission_type="unicast", dst_ip="10.0.0.2")
    assert j["meta"]["transmission_type"] == "unicast"
    assert j["meta"]["dst_ips"] == ["10.0.0.2"]
    assert len(j["deliveries_summary"]) == 1
    assert "fragments" in j and len(j["fragments"]) > 0

def test_broadcast_process():
    j = _process(transmission_type="broadcast")
    assert j["meta"]["transmission_type"] == "broadcast"
    assert j["meta"]["dst_ips"] == ["255.255.255.255"]
    assert len(j["deliveries_summary"]) == 1

def test_multicast_process():
    j = _process(transmission_type="multicast", dst_list="10.0.0.2,10.0.0.3")
    assert j["meta"]["transmission_type"] == "multicast"
    assert set(j["meta"]["dst_ips"]) == {"10.0.0.2", "10.0.0.3"}
    assert len(j["deliveries_summary"]) == 2

def test_reassemble_by_destination():
    j = _process(transmission_type="multicast", dst_list="10.0.0.2,10.0.0.3")
    pid = j["pid"]
    targets = j["meta"]["dst_ips"]
    # Elige el segundo destino (si existe)
    dst = targets[1] if len(targets) > 1 else targets[0]
    r = client.post("/reassemble", data={"pid": pid, "dst_ip": dst})
    assert r.status_code == 200, r.text
    jj = r.json()
    assert jj.get("status") == "ok"
    assert jj.get("dst_ip") == dst
