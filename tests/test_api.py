from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from aegis import api


client = TestClient(api.app)


def test_config_endpoint_selects_mode_from_status(monkeypatch) -> None:
    snapshots = [
        {
            'live': False,
            'mode': 'server',
            'config_file': 'server.conf',
            'config': {'mode': 'server'},
            'key_dir': 'N/A',
            'key_files': [],
        },
        {
            'live': False,
            'mode': 'client',
            'config_file': 'client.conf',
            'config': {'mode': 'client'},
            'key_dir': 'N/A',
            'key_files': [],
        },
    ]

    monkeypatch.setattr(api, '_config_snapshot_from_live', lambda: None)
    monkeypatch.setattr(api, '_fallback_config_snapshots', lambda: snapshots)
    monkeypatch.setattr(api._state, 'read_status_file', lambda: {'mode': 'client'})

    response = client.get('/api/config')

    assert response.status_code == 200
    payload = response.json()
    assert payload['mode'] == 'client'
    assert payload['config_file'] == 'client.conf'
    assert len(payload['available_configs']) == 2


def test_config_endpoint_returns_503_when_unavailable(monkeypatch) -> None:
    monkeypatch.setattr(api, '_config_snapshot_from_live', lambda: None)
    monkeypatch.setattr(api, '_fallback_config_snapshots', lambda: [])

    response = client.get('/api/config')

    assert response.status_code == 503


def test_keygen_endpoint_generates_x25519_files(monkeypatch, tmp_path: Path) -> None:
    key_dir = tmp_path / 'keys'

    monkeypatch.setattr(
        api,
        '_config_snapshot_from_live',
        lambda: {
            'live': True,
            'mode': 'client',
            'config_file': 'live',
            'config': {'mode': 'client'},
            'key_dir': str(key_dir),
            'key_files': [],
        },
    )

    response = client.post('/api/keygen')

    assert response.status_code == 200
    payload = response.json()
    assert payload['output_dir'] == str(key_dir)
    assert (key_dir / 'x25519_priv.bin').exists()
    assert (key_dir / 'x25519_pub.bin').exists()


def test_keygen_endpoint_returns_503_without_config(monkeypatch) -> None:
    monkeypatch.setattr(api, '_config_snapshot_from_live', lambda: None)
    monkeypatch.setattr(api, '_fallback_config_snapshots', lambda: [])

    response = client.post('/api/keygen')

    assert response.status_code == 503
