from __future__ import annotations

import json
import shutil
import tempfile
from contextlib import contextmanager
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urlparse

from .artifacts import pretty_json_text
from .example_specs import FIXTURE_SPECS
from .paths import find_repo_root, override_repo_root
from .transparency import build_transparency_log
from .verifier import verify_fixture_consistency


DEFAULT_VERIFY_API_HOST = "127.0.0.1"
DEFAULT_VERIFY_API_PORT = 8788

_DEFAULT_OSCAL_MAPPING_FILES = {
    "minimal": "iso27001-soc2-family-overlap-mapping.json",
    "failed": "iso27001-soc2-family-overlap-mapping.json",
    "stale": "iso27001-soc2-family-overlap-mapping.json",
    "medium": "iso27001-soc2-irap-gdpr-family-overlap-mapping.json",
    "issued": "iso27001-soc2-irap-family-overlap-mapping.json",
    "cyber-baseline": "cyber-essentials-baseline-family-overlap-mapping.json",
    "ai-governance": "ai-governance-family-overlap-mapping.json",
}

_API_ENDPOINTS = {
    "healthz": {"method": "GET", "path": "/healthz"},
    "fixtures": {"method": "GET", "path": "/fixtures"},
    "contract": {"method": "GET", "path": "/contract"},
    "verify": {"method": "POST", "path": "/verify"},
}

_ARTIFACT_KEY_BY_FILENAME = {
    "classification-result.json": "classificationResult",
    "proof-bundle.json": "proofBundle",
    "trust-surface-report.md": "trustSurfaceReport",
    "verification-result.json": "verificationResult",
    "certificate.json": "certificate",
    "punch-list.json": "punchList",
    "replay-bundle.json": "replayBundle",
    "witness-receipt.json": "witnessReceipt",
    "revocation.json": "revocation",
}


class VerificationRequestError(ValueError):
    """Raised when the local Verify API request body is malformed."""


def project_root() -> Path:
    return find_repo_root(Path(__file__))


def available_fixture_names() -> list[str]:
    return sorted(FIXTURE_SPECS)


def run_verify(fixture_root: Path) -> dict[str, str]:
    """Return the full deterministic artifact set for a fixture root."""
    return verify_fixture_consistency(fixture_root)


def load_verifier_contract(repo_root: Path | None = None) -> dict[str, Any]:
    repo_root = (repo_root or project_root()).resolve()
    return json.loads((repo_root / "open-specs" / "verifier-contract.json").read_text(encoding="utf-8"))


def api_surface_document(repo_root: Path | None = None) -> dict[str, Any]:
    contract = load_verifier_contract(repo_root)
    return {
        "service": "opencompliance-verify-api",
        "verifierVersion": contract["verifierVersion"],
        "defaultHost": DEFAULT_VERIFY_API_HOST,
        "defaultPort": DEFAULT_VERIFY_API_PORT,
        "supportedFixtures": available_fixture_names(),
        "requestModes": ["fixture_path", "inline_bundle"],
        "endpoints": _API_ENDPOINTS,
    }


def _default_fixture_root(repo_root: Path, fixture_name: str) -> Path:
    return repo_root / "fixtures" / "public" / fixture_name


def _ensure_supported_fixture_name(fixture_name: str) -> None:
    if fixture_name not in FIXTURE_SPECS:
        supported = ", ".join(available_fixture_names())
        raise VerificationRequestError(
            f"Unsupported fixtureName '{fixture_name}'. Supported fixtures: {supported}"
        )


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(pretty_json_text(payload), encoding="utf-8")


def _copy_required_source_files(source_root: Path, temp_root: Path) -> None:
    for name in ("profile.json", "evidence-claims.json"):
        source_path = source_root / name
        if not source_path.exists():
            raise VerificationRequestError(f"fixture_path input is missing required file: {source_path}")
        destination = temp_root / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_path, destination)


def _copy_or_seed_oscal(
    source_root: Path | None,
    temp_root: Path,
    repo_root: Path,
    fixture_name: str,
    *,
    use_default_seed: bool,
) -> None:
    if source_root is not None:
        source_oscal = source_root / "oscal"
        if source_oscal.exists():
            shutil.copytree(source_oscal, temp_root / "oscal", dirs_exist_ok=True)
            return
    if not use_default_seed:
        raise VerificationRequestError("Request did not include OSCAL material and useDefaultOscalSeed is false.")
    default_oscal = _default_fixture_root(repo_root, fixture_name) / "oscal"
    if not default_oscal.exists():
        raise VerificationRequestError(f"No default OSCAL seed exists for fixture '{fixture_name}'.")
    shutil.copytree(default_oscal, temp_root / "oscal", dirs_exist_ok=True)


def _write_inline_oscal(temp_root: Path, fixture_name: str, oscal: dict[str, Any]) -> None:
    required = ("catalog", "profile", "ssp", "mappingCollection")
    missing = [key for key in required if key not in oscal]
    if missing:
        raise VerificationRequestError(
            "inline_bundle.oscal is missing required entries: " + ", ".join(sorted(missing))
        )
    oscal_root = temp_root / "oscal"
    _write_json(oscal_root / f"opencompliance-{fixture_name}-catalog.json", oscal["catalog"])
    _write_json(oscal_root / f"exampleco-{fixture_name}-profile.json", oscal["profile"])
    _write_json(oscal_root / f"exampleco-{fixture_name}-ssp.json", oscal["ssp"])
    _write_json(oscal_root / _DEFAULT_OSCAL_MAPPING_FILES[fixture_name], oscal["mappingCollection"])
    if "assessmentPlan" in oscal:
        _write_json(oscal_root / f"exampleco-{fixture_name}-assessment-plan.json", oscal["assessmentPlan"])


@contextmanager
def _materialized_fixture_root(
    request: dict[str, Any],
    *,
    repo_root: Path,
) -> Iterator[Path]:
    fixture_name = request.get("fixtureName")
    if not isinstance(fixture_name, str) or not fixture_name:
        raise VerificationRequestError("fixtureName is required and must be a non-empty string.")
    _ensure_supported_fixture_name(fixture_name)

    input_payload = request.get("input")
    if not isinstance(input_payload, dict):
        raise VerificationRequestError("input is required and must be an object.")

    mode = input_payload.get("mode")
    if mode not in {"fixture_path", "inline_bundle"}:
        raise VerificationRequestError("input.mode must be one of: fixture_path, inline_bundle.")

    with tempfile.TemporaryDirectory() as temp_dir_raw:
        temp_root = Path(temp_dir_raw) / fixture_name
        temp_root.mkdir(parents=True, exist_ok=True)

        if mode == "fixture_path":
            fixture_root_raw = input_payload.get("fixtureRoot")
            if not isinstance(fixture_root_raw, str) or not fixture_root_raw:
                raise VerificationRequestError("fixture_path mode requires input.fixtureRoot.")
            source_root = Path(fixture_root_raw).resolve()
            if not source_root.exists() or not source_root.is_dir():
                raise VerificationRequestError(f"fixtureRoot does not exist or is not a directory: {source_root}")
            _copy_required_source_files(source_root, temp_root)
            _copy_or_seed_oscal(
                source_root,
                temp_root,
                repo_root,
                fixture_name,
                use_default_seed=bool(input_payload.get("useDefaultOscalSeed", False)),
            )
        else:
            if not isinstance(input_payload.get("profile"), dict):
                raise VerificationRequestError("inline_bundle mode requires input.profile.")
            evidence_claims = input_payload.get("evidenceClaims")
            if not isinstance(evidence_claims, list):
                raise VerificationRequestError("inline_bundle mode requires input.evidenceClaims.")
            _write_json(temp_root / "profile.json", input_payload["profile"])
            _write_json(temp_root / "evidence-claims.json", evidence_claims)
            inline_oscal = input_payload.get("oscal")
            if inline_oscal is not None:
                if not isinstance(inline_oscal, dict):
                    raise VerificationRequestError("input.oscal must be an object when provided.")
                _write_inline_oscal(temp_root, fixture_name, inline_oscal)
            else:
                _copy_or_seed_oscal(
                    None,
                    temp_root,
                    repo_root,
                    fixture_name,
                    use_default_seed=bool(input_payload.get("useDefaultOscalSeed", True)),
                )

        yield temp_root


def _write_generated_artifacts(temp_root: Path, generated: dict[str, str]) -> dict[str, Any]:
    artifacts: dict[str, Any] = {}
    for name, content in generated.items():
        if name == "fixture":
            continue
        path = temp_root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        if name.endswith(".json"):
            payload: Any = json.loads(content)
        else:
            payload = content
        artifact_key = _ARTIFACT_KEY_BY_FILENAME.get(name)
        if artifact_key is None and name.endswith("-assessment-results.json"):
            artifact_key = "oscalAssessmentResults"
        if artifact_key is None:
            raise VerificationRequestError(f"Unexpected generated artifact: {name}")
        artifacts[artifact_key] = payload

    proof_bundle = artifacts["proofBundle"]
    transparency_log, inclusion_proofs = build_transparency_log(temp_root, proof_bundle["generatedAt"])
    artifacts["transparencyLog"] = transparency_log
    artifacts["inclusionProofs"] = inclusion_proofs
    return artifacts


def verify_request(request: dict[str, Any], *, repo_root: Path | None = None) -> dict[str, Any]:
    repo_root = (repo_root or project_root()).resolve()
    with _materialized_fixture_root(request, repo_root=repo_root) as fixture_root:
        with override_repo_root(repo_root):
            generated = run_verify(fixture_root)
        artifacts = _write_generated_artifacts(fixture_root, generated)
        verification_result = artifacts["verificationResult"]
        proof_bundle = artifacts["proofBundle"]
        return {
            "service": "opencompliance-verify-api",
            "fixtureName": fixture_root.name,
            "bundleId": proof_bundle["bundleId"],
            "profileId": proof_bundle["profileId"],
            "organisation": proof_bundle["organisation"],
            "verificationOutcome": verification_result["outcome"],
            "artifacts": artifacts,
        }


class VerifyApiServer(ThreadingHTTPServer):
    def __init__(self, server_address: tuple[str, int], repo_root: Path):
        super().__init__(server_address, VerifyApiHandler)
        self.repo_root = repo_root


class VerifyApiHandler(BaseHTTPRequestHandler):
    server_version = "OpenComplianceVerifyAPI/0.1"

    def log_message(self, format: str, *args: object) -> None:  # noqa: A003 - stdlib signature
        return

    @property
    def repo_root(self) -> Path:
        return self.server.repo_root  # type: ignore[attr-defined]

    def _write_json_response(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
        body = pretty_json_text(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:  # noqa: N802 - stdlib signature
        self.send_response(HTTPStatus.NO_CONTENT)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _read_json_body(self) -> dict[str, Any]:
        content_length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(content_length)
        if not raw:
            raise VerificationRequestError("Request body is required.")
        try:
            payload = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise VerificationRequestError(f"Request body is not valid JSON: {exc.msg}") from exc
        if not isinstance(payload, dict):
            raise VerificationRequestError("Request body must be a JSON object.")
        return payload

    def do_GET(self) -> None:  # noqa: N802 - stdlib signature
        path = urlparse(self.path).path
        if path == _API_ENDPOINTS["healthz"]["path"]:
            self._write_json_response(
                HTTPStatus.OK,
                {
                    "status": "ok",
                    "service": "opencompliance-verify-api",
                    "verifierVersion": load_verifier_contract(self.repo_root)["verifierVersion"],
                    "supportedFixtures": available_fixture_names(),
                },
            )
            return
        if path == _API_ENDPOINTS["fixtures"]["path"]:
            self._write_json_response(
                HTTPStatus.OK,
                {
                    "supportedFixtures": available_fixture_names(),
                    "note": "The current local API remains tied to the known synthetic/public corridor shapes.",
                },
            )
            return
        if path == _API_ENDPOINTS["contract"]["path"]:
            self._write_json_response(HTTPStatus.OK, load_verifier_contract(self.repo_root))
            return
        self._write_json_response(HTTPStatus.NOT_FOUND, {"error": "not_found", "path": path})

    def do_POST(self) -> None:  # noqa: N802 - stdlib signature
        path = urlparse(self.path).path
        if path != _API_ENDPOINTS["verify"]["path"]:
            self._write_json_response(HTTPStatus.NOT_FOUND, {"error": "not_found", "path": path})
            return
        try:
            request = self._read_json_body()
            response = verify_request(request, repo_root=self.repo_root)
        except VerificationRequestError as exc:
            self._write_json_response(HTTPStatus.BAD_REQUEST, {"error": "invalid_request", "message": str(exc)})
            return
        except Exception as exc:  # pragma: no cover - surfaced in tests via 500 path only on regression
            self._write_json_response(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "verification_failed", "message": str(exc)})
            return
        self._write_json_response(HTTPStatus.OK, response)


def make_verify_api_server(
    repo_root: Path | None = None,
    *,
    host: str = DEFAULT_VERIFY_API_HOST,
    port: int = DEFAULT_VERIFY_API_PORT,
) -> VerifyApiServer:
    return VerifyApiServer((host, port), (repo_root or project_root()).resolve())


def serve_verify_api(
    repo_root: Path | None = None,
    *,
    host: str = DEFAULT_VERIFY_API_HOST,
    port: int = DEFAULT_VERIFY_API_PORT,
) -> None:
    server = make_verify_api_server(repo_root, host=host, port=port)
    try:
        server.serve_forever()
    finally:
        server.server_close()
