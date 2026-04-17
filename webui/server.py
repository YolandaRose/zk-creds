import json
import os
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse

PORT = 8000
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

SCENARIOS = {
    "bank_loan": {
        "label": "Bank Loan (age >= 18)",
        "rule": lambda attrs: int(attrs.get("age", 0)) >= 18,
    },
    "cross_border": {
        "label": "Cross Border (country == CN)",
        "rule": lambda attrs: attrs.get("country") == "CN",
    },
    "membership": {
        "label": "VIP Membership (score >= 600)",
        "rule": lambda attrs: int(attrs.get("score", 0)) >= 600,
    },
}

STATE = {
    "attrs": {},
    "commitment": None,
    "credential_id": None,
    "merkle_root": None,
    "revoked": False,
    "last_proof": None,
    "proof_seq": 0,
}

class DashboardHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=BASE_DIR, **kwargs)

    def do_GET(self):
        if self.path == "/":
            self.path = "/dashboard.html"
            return super().do_GET()
        if self.path == "/api/scenarios":
            scenario_list = [
                {"id": sid, "label": info["label"]} for sid, info in SCENARIOS.items()
            ]
            return self.send_json({"scenarios": scenario_list})
        if self.path == "/api/state":
            return self.send_json(
                {
                    "attrs": STATE["attrs"],
                    "commitment": STATE["commitment"],
                    "credential": STATE["credential_id"],
                    "root": STATE["merkle_root"],
                    "revoked": STATE["revoked"],
                    "last_proof": STATE["last_proof"],
                }
            )
        return super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        if not parsed.path.startswith("/api/"):
            return self.send_error(404, "Not found")

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8") if length else ""
        payload = {}
        if body:
            try:
                payload = json.loads(body)
            except json.JSONDecodeError:
                return self.send_json({"error": "Invalid JSON payload"}, code=400)

        if parsed.path == "/api/commit":
            attrs = payload.get("attrs", {})
            if not isinstance(attrs, dict):
                return self.send_json({"error": "`attrs` must be a JSON object"}, code=400)
            commitment = f"0xcommit_{abs(hash(json.dumps(attrs, sort_keys=True))) % 10**10:010d}"
            STATE["attrs"] = attrs
            STATE["commitment"] = commitment
            STATE["credential_id"] = None
            STATE["merkle_root"] = None
            STATE["revoked"] = False
            STATE["last_proof"] = None
            return self.send_json({
                "commitment": commitment,
                "attrs": attrs,
            })
        if parsed.path == "/api/issue":
            if not STATE["commitment"]:
                return self.send_json(
                    {"error": "Please generate commitment first"}, code=400
                )
            credential_id = f"cred_{abs(hash(STATE['commitment'])) % 10**8:08d}"
            STATE["credential_id"] = credential_id
            STATE["revoked"] = False
            STATE["last_proof"] = None
            return self.send_json({"credential": credential_id})
        if parsed.path == "/api/merkle":
            if not STATE["credential_id"]:
                return self.send_json(
                    {"error": "Please issue credential first"}, code=400
                )
            root = f"0xroot_{abs(hash(STATE['credential_id'])) % 10**8:08d}"
            STATE["merkle_root"] = root
            return self.send_json({"root": root})
        if parsed.path == "/api/prove":
            if not STATE["credential_id"]:
                return self.send_json(
                    {"error": "No issued credential, cannot prove"}, code=400
                )
            scenario_id = payload.get("scenario")
            if scenario_id not in SCENARIOS:
                return self.send_json({"error": "Invalid scenario"}, code=400)
            STATE["proof_seq"] += 1
            scenario = SCENARIOS[scenario_id]
            passed_rule = bool(scenario["rule"](STATE["attrs"]))
            proof = f"proof_{STATE['proof_seq']:04d}_{scenario_id}"
            STATE["last_proof"] = {
                "proof": proof,
                "scenario": scenario_id,
                "scenario_label": scenario["label"],
                "credential": STATE["credential_id"],
                "revoked": STATE["revoked"],
                "passed_rule": passed_rule,
            }
            return self.send_json(STATE["last_proof"])
        if parsed.path == "/api/verify":
            if not STATE["last_proof"]:
                return self.send_json({"error": "No proof generated yet"}, code=400)
            result = (
                (not STATE["revoked"])
                and STATE["last_proof"]["credential"] == STATE["credential_id"]
                and STATE["last_proof"]["passed_rule"]
            )
            reason = "ok"
            if STATE["revoked"]:
                reason = "credential revoked by issuer"
            elif not STATE["last_proof"]["passed_rule"]:
                reason = "attribute policy check failed for scenario"
            return self.send_json(
                {
                    "result": result,
                    "reason": reason,
                    "scenario": STATE["last_proof"]["scenario"],
                    "credential": STATE["last_proof"]["credential"],
                }
            )
        if parsed.path == "/api/revoke":
            if not STATE["credential_id"]:
                return self.send_json({"error": "No issued credential to revoke"}, code=400)
            STATE["revoked"] = True
            return self.send_json(
                {
                    "revoked": True,
                    "credential": STATE["credential_id"],
                    "message": "Credential revoked by issuer",
                }
            )

        self.send_error(404, "Not found")

    def send_json(self, data, code=200):
        payload = json.dumps(data).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def run(server_class=HTTPServer, handler_class=DashboardHandler):
    server_address = ("", PORT)
    httpd = server_class(server_address, handler_class)
    print(f"Serving dashboard at http://localhost:{PORT}/")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("Shutting down server")
        httpd.server_close()

if __name__ == "__main__":
    run()
