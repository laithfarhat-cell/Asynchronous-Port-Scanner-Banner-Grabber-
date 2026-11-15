"""The local preview console (scripts/preview_server.py) must stay healthy.

It is a dev convenience, but it is also what the workspace preview serves, so a
broken template or a bad route should fail CI rather than a browser tab.
"""

from __future__ import annotations

import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from scripts.preview_server import (
    CONSOLE_BUILD,
    PreviewHandler,
    active_json,
    active_report,
    render_index,
)


@pytest.fixture(scope="module")
def base_url():
    server = ThreadingHTTPServer(("127.0.0.1", 0), PreviewHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def get(url: str):
    with urllib.request.urlopen(url, timeout=10) as response:
        return response.status, response.read(), response.headers.get("Content-Type", "")


class TestRender:
    def test_index_has_no_unrendered_placeholders(self):
        html = render_index()
        for placeholder in ("{open_ports}", "{rows}", "{sig_rows}", "{help_text}", "{rules}"):
            assert placeholder not in html
        assert html.startswith("<!DOCTYPE html>")

    def test_index_is_self_contained(self):
        html = render_index()
        assert "http://" not in html and "https://" not in html  # no CDN calls
        assert "<style>" in html and "<script>" in html

    def test_index_shows_findings_and_cli(self):
        html = render_index()
        assert "Open ports" in html and "Signatures" in html and "CLI reference" in html
        assert "--top-ports" in html          # rendered from `main.py --help`
        assert "ssh-openssh" in html or "http-nginx" in html  # signature table
        assert "127.0.0.1" in html            # demo findings

    def test_page_exposes_its_build(self):
        """The rendered page must identify its build so a stale process is visible."""
        html = render_index()
        assert f"build {CONSOLE_BUILD}" in html
        assert "{build}" not in html and "{started}" not in html

    def test_report_sources_resolve(self):
        assert active_report() is not None and active_report().is_file()
        assert active_json() is not None and active_json().is_file()


class TestRoutes:
    @pytest.mark.parametrize("path", ["/", "/index.html", "/healthz", "/reports/demo",
                                      "/reports/demo.json", "/reports/demo.csv",
                                      "/api/signatures", "/api/ports", "/api/help"])
    def test_routes_ok(self, base_url, path):
        status, body, _ctype = get(base_url + path)
        assert status == 200 and body

    def test_index_served_as_html(self, base_url):
        status, body, ctype = get(base_url + "/")
        assert status == 200 and "text/html" in ctype and b"asynscan" in body

    def test_healthz_json(self, base_url):
        import json

        status, body, ctype = get(base_url + "/healthz")
        payload = json.loads(body)
        assert status == 200 and "application/json" in ctype
        assert payload["status"] == "ok"
        # Identity fields are what make a stale process detectable.
        assert payload["console_build"] == CONSOLE_BUILD
        assert payload["started_at"]
        assert payload["report"] and payload["data"]
        assert payload["report"].endswith(".html") and payload["data"].endswith(".json")

    def test_signature_api_matches_database(self, base_url):
        import json

        from core.banner_grabber import SignatureDatabase

        _status, body, _ctype = get(base_url + "/api/signatures")
        payload = json.loads(body)
        assert payload["count"] == len(SignatureDatabase.load()) == len(payload["rules"])
        assert all(rule["pattern"] for rule in payload["rules"])

    def test_ports_api(self, base_url):
        import json

        _status, body, _ctype = get(base_url + "/api/ports")
        payload = json.loads(body)
        assert len(payload["top_100"]) == 100 and len(payload["top_1000"]) == 1000

    def test_unknown_route_is_404(self, base_url):
        with pytest.raises(urllib.error.HTTPError) as excinfo:
            get(base_url + "/nope")
        assert excinfo.value.code == 404

    def test_host_header_from_preview_proxy_is_accepted(self, base_url):
        """The preview proxy forwards a *.e2b.app Host header; it must not 400."""
        import http.client

        target = base_url.removeprefix("http://")
        host, port = target.split(":")
        conn = http.client.HTTPConnection(host, int(port), timeout=10)
        try:
            conn.request("GET", "/", headers={"Host": "32929-abc123.e2b.app"})
            response = conn.getresponse()
            assert response.status == 200
            assert b"asynscan" in response.read()
        finally:
            conn.close()

    def test_head_request_supported(self, base_url):
        import http.client

        target = base_url.removeprefix("http://")
        host, port = target.split(":")
        conn = http.client.HTTPConnection(host, int(port), timeout=10)
        try:
            conn.request("HEAD", "/")
            response = conn.getresponse()
            assert response.status == 200 and int(response.getheader("Content-Length", 0)) > 1000
        finally:
            conn.close()
