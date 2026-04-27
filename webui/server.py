import json
import os
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse

PORT = 8000
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CARD_TODAY = 20220101
PASSPORT_TODAY = 20220101
TICKET_THRESHOLD_DOB = 20040101

SCENARIOS = {
    "student_employee": {
        "label": "学生-员工：校企合作",
        "description": "姓名一致 + 学校/公司匹配 + 学生证/工卡有效期",
    },
    "passport_student": {
        "label": "护照-学生：国际优惠",
        "description": "姓名一致 + 国籍匹配 + 年龄门槛 + 护照/学生证有效期",
    },
    "passport_employee": {
        "label": "护照-员工：跨境商务",
        "description": "姓名一致 + 公司匹配 + 护照/工卡有效期",
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


def _as_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _build_commitment(attrs, revoked=False):
    payload = {
        "attrs": attrs,
        "revoked": revoked,
    }
    return f"0xcommit_{abs(hash(json.dumps(payload, sort_keys=True))) % 10**10:010d}"


def _build_merkle_root(credential_id, commitment, revoked=False):
    payload = {
        "credential": credential_id,
        "commitment": commitment,
        "revoked": revoked,
    }
    return f"0xroot_{abs(hash(json.dumps(payload, sort_keys=True))) % 10**8:08d}"


def _check_student_employee(attrs):
    ok = True
    reasons = []
    checks = {}

    name_equal = attrs.get("student_name", "") == attrs.get("employee_name", "")
    checks["name_equal"] = name_equal
    ok = ok and name_equal
    if not name_equal:
        reasons.append("学生证姓名与员工证姓名不一致")

    school_match = attrs.get("student_school", "") == attrs.get("expected_school", "")
    checks["school_match"] = school_match
    ok = ok and school_match
    if not school_match:
        reasons.append("学生证学校与场景要求不匹配")

    company_match = attrs.get("employee_company", "") == attrs.get("expected_company", "")
    checks["company_match"] = company_match
    ok = ok and company_match
    if not company_match:
        reasons.append("员工证公司与场景要求不匹配")

    student_expiry_ok = _as_int(attrs.get("student_card_expiry")) > CARD_TODAY
    checks["student_expiry_gt_today"] = student_expiry_ok
    ok = ok and student_expiry_ok
    if not student_expiry_ok:
        reasons.append(f"学生证已过期或无效（需 > {CARD_TODAY}）")

    employee_expiry_ok = _as_int(attrs.get("employee_card_expiry")) > CARD_TODAY
    checks["employee_expiry_gt_today"] = employee_expiry_ok
    ok = ok and employee_expiry_ok
    if not employee_expiry_ok:
        reasons.append(f"员工证已过期或无效（需 > {CARD_TODAY}）")

    return {"ok": ok, "checks": checks, "reasons": reasons}


def _check_passport_student(attrs):
    ok = True
    reasons = []
    checks = {}

    name_equal = attrs.get("student_name", "") == attrs.get("passport_name", "")
    checks["name_equal"] = name_equal
    ok = ok and name_equal
    if not name_equal:
        reasons.append("学生证姓名与护照姓名不一致")

    nationality_match = attrs.get("passport_nationality", "") == attrs.get(
        "expected_nationality", ""
    )
    checks["nationality_match"] = nationality_match
    ok = ok and nationality_match
    if not nationality_match:
        reasons.append("护照国籍与场景要求不匹配")

    dob_ok = _as_int(attrs.get("passport_dob")) <= TICKET_THRESHOLD_DOB
    checks["dob_le_threshold"] = dob_ok
    ok = ok and dob_ok
    if not dob_ok:
        reasons.append(f"年龄条件不满足（需 DOB <= {TICKET_THRESHOLD_DOB}）")

    passport_expiry_ok = _as_int(attrs.get("passport_expiry")) > PASSPORT_TODAY
    checks["passport_expiry_gt_today"] = passport_expiry_ok
    ok = ok and passport_expiry_ok
    if not passport_expiry_ok:
        reasons.append(f"护照已过期或无效（需 > {PASSPORT_TODAY}）")

    student_expiry_ok = _as_int(attrs.get("student_card_expiry")) > CARD_TODAY
    checks["student_expiry_gt_today"] = student_expiry_ok
    ok = ok and student_expiry_ok
    if not student_expiry_ok:
        reasons.append(f"学生证已过期或无效（需 > {CARD_TODAY}）")

    return {"ok": ok, "checks": checks, "reasons": reasons}


def _check_passport_employee(attrs):
    ok = True
    reasons = []
    checks = {}

    name_equal = attrs.get("employee_name", "") == attrs.get("passport_name", "")
    checks["name_equal"] = name_equal
    ok = ok and name_equal
    if not name_equal:
        reasons.append("员工证姓名与护照姓名不一致")

    company_match = attrs.get("employee_company", "") == attrs.get("expected_company", "")
    checks["company_match"] = company_match
    ok = ok and company_match
    if not company_match:
        reasons.append("员工证公司与场景要求不匹配")

    passport_expiry_ok = _as_int(attrs.get("passport_expiry")) > PASSPORT_TODAY
    checks["passport_expiry_gt_today"] = passport_expiry_ok
    ok = ok and passport_expiry_ok
    if not passport_expiry_ok:
        reasons.append(f"护照已过期或无效（需 > {PASSPORT_TODAY}）")

    employee_expiry_ok = _as_int(attrs.get("employee_card_expiry")) > CARD_TODAY
    checks["employee_expiry_gt_today"] = employee_expiry_ok
    ok = ok and employee_expiry_ok
    if not employee_expiry_ok:
        reasons.append(f"员工证已过期或无效（需 > {CARD_TODAY}）")

    return {"ok": ok, "checks": checks, "reasons": reasons}


SCENARIO_CHECKERS = {
    "student_employee": _check_student_employee,
    "passport_student": _check_passport_student,
    "passport_employee": _check_passport_employee,
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
                {
                    "id": sid,
                    "label": info["label"],
                    "description": info["description"],
                }
                for sid, info in SCENARIOS.items()
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
                return self.send_json({"error": "JSON 载荷格式无效"}, code=400)

        if parsed.path == "/api/commit":
            attrs = payload.get("attrs", {})
            if not isinstance(attrs, dict):
                return self.send_json({"error": "`attrs` 必须是 JSON 对象"}, code=400)
            commitment = _build_commitment(attrs, revoked=False)
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
                    {"error": "请先生成承诺"}, code=400
                )
            credential_id = f"cred_{abs(hash(STATE['commitment'])) % 10**8:08d}"
            STATE["credential_id"] = credential_id
            STATE["revoked"] = False
            STATE["last_proof"] = None
            return self.send_json({"credential": credential_id})
        if parsed.path == "/api/merkle":
            if not STATE["credential_id"]:
                return self.send_json(
                    {"error": "请先签发凭证"}, code=400
                )
            root = _build_merkle_root(
                STATE["credential_id"],
                STATE["commitment"],
                STATE["revoked"],
            )
            STATE["merkle_root"] = root
            return self.send_json({"root": root})
        if parsed.path == "/api/prove":
            if not STATE["credential_id"]:
                return self.send_json(
                    {"error": "尚未签发凭证，无法生成证明"}, code=400
                )
            scenario_id = payload.get("scenario")
            if scenario_id not in SCENARIOS:
                return self.send_json({"error": "认证场景无效"}, code=400)
            checker = SCENARIO_CHECKERS[scenario_id]
            scenario_eval = checker(STATE["attrs"])
            STATE["proof_seq"] += 1
            scenario = SCENARIOS[scenario_id]
            proof = f"proof_{STATE['proof_seq']:04d}_{scenario_id}"
            STATE["last_proof"] = {
                "proof": proof,
                "scenario": scenario_id,
                "scenario_label": scenario["label"],
                "credential": STATE["credential_id"],
                "revoked": STATE["revoked"],
                "passed_rule": scenario_eval["ok"],
                "checks": scenario_eval["checks"],
                "reasons": scenario_eval["reasons"],
            }
            return self.send_json(STATE["last_proof"])
        if parsed.path == "/api/verify":
            if not STATE["last_proof"]:
                return self.send_json({"error": "尚未生成证明"}, code=400)
            result = (
                (not STATE["revoked"])
                and STATE["last_proof"]["credential"] == STATE["credential_id"]
                and STATE["last_proof"]["passed_rule"]
            )
            reason = "通过"
            if STATE["revoked"]:
                reason = "凭证已被发行方撤销"
            elif not STATE["last_proof"]["passed_rule"]:
                details = "；".join(STATE["last_proof"].get("reasons", []))
                reason = f"未满足该场景的联合谓词：{details}"
            return self.send_json(
                {
                    "result": result,
                    "reason": reason,
                    "scenario": STATE["last_proof"]["scenario"],
                    "credential": STATE["last_proof"]["credential"],
                    "checks": STATE["last_proof"].get("checks", {}),
                }
            )
        if parsed.path == "/api/revoke":
            if not STATE["credential_id"]:
                return self.send_json({"error": "当前没有可撤销的已签发凭证"}, code=400)
            STATE["revoked"] = True
            # 撤销后重算承诺值，保证与未撤销状态区分。
            STATE["commitment"] = _build_commitment(STATE["attrs"], revoked=True)
            STATE["merkle_root"] = _build_merkle_root(
                STATE["credential_id"],
                STATE["commitment"],
                STATE["revoked"],
            )
            return self.send_json(
                {
                    "revoked": True,
                    "credential": STATE["credential_id"],
                    "commitment": STATE["commitment"],
                    "root": STATE["merkle_root"],
                    "message": "发行方已撤销凭证",
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
