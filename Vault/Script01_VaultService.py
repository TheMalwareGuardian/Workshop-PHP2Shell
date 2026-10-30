"""Internal fictional vault for the PHP2Shell classroom challenge."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hmac
import json
import secrets
from pathlib import Path

KEY = secrets.token_urlsafe(24)
key_file = Path("/run/workshop/vault.key")
# The PHP container sees this file through a read-only shared volume. The browser cannot reach the private vault network or read the key directly.
key_file.write_text(KEY + "\n", encoding="utf-8")
key_file.chmod(0o644)
PROOF = "PHP2SHELL{" + secrets.token_hex(12) + "}"
# Generate account records once, so repeated student requests see the same ledger state for the lifetime of this vault process.
ACCOUNTS = [
	{"user": "ledger-reader",
	"password": "TRAINING_ONLY_" + secrets.token_hex(6)},
	{"user": "backup-operator",
	"password": "TRAINING_ONLY_" + secrets.token_hex(6)},
]

class Handler(BaseHTTPRequestHandler):
	"""Serve health freely and require the runtime key for ledger routes."""

	def do_GET(self):
		"""Return records or wallet data only after header authentication."""
		# Health is unauthenticated so Compose can wait for the service.
		if self.path == "/health":
			return self.reply(200, {"status": "ok"})
		# Every other route requires the key generated for this container run.
		supplied = self.headers.get("X-Vault-Key", "")
		if not hmac.compare_digest(supplied, KEY):
			return self.reply(403, {"error": "vault key required"})
		if self.path == "/":
			return self.reply(200, {"service": "Workshop Ledger Vault", "routes": ["/records", "/wallet"]})
		if self.path == "/records":
			return self.reply(200, {
				"accounts": ACCOUNTS,
				"note": "The wallet endpoint holds the final proof."})
		if self.path == "/wallet":
			return self.reply(200, {
				"wallet": "VAULT-LEDGER-001",
				"recovery_phrase": "velvet orbit paper lantern river",
				"proof": PROOF})
		return self.reply(404, {"error": "not found"})

	def reply(self, status, payload):
		"""Serialize one JSON response with an explicit byte length."""
		body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
		self.send_response(status)
		self.send_header("Content-Type", "application/json; charset=utf-8")
		self.send_header("Content-Length", str(len(body)))
		self.end_headers()
		self.wfile.write(body)

ThreadingHTTPServer(("0.0.0.0", 9000), Handler).serve_forever()
