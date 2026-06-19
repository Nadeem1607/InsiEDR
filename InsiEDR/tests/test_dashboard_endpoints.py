from server.app import create_app


def test_dashboard_renders():
    app = create_app(storage=None, apply_migrations=False)
    client = app.test_client()
    resp = client.get("/dashboard/")
    assert resp.status_code == 200
    assert b"InsiEDR" in resp.data
