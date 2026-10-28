"""Alfa Payment Gateway (APG) - Bank Alfalah, on the property's own APG
account.

APG is a *redirect* gateway, not a hosted payment link: the desk's link is a
Kamra page (www/apg_checkout) that performs APG's two-step handshake and posts
the guest straight on to APG's secure checkout. Money is confirmed by asking
APG for the order's status, never by trusting a callback body.

Flow, per the APG Merchant Integration Guide v1.1 (page redirection):
  1. handshake()  - POST the HS_* fields (with HS_RequestHash) to /HS/HS/HS,
     which returns an AuthToken
  2. the guest's browser POSTs the SSO fields (with RequestHash + AuthToken)
     to /SSO/SSO/SSO -> APG's card / wallet checkout page
  3. APG returns the guest to ReturnURL as ?O=<order reference>
  4. order_status() / verify_webhook() - GET the IPN OrderStatus URL for the
     authoritative ResponseCode + TransactionStatus

The RequestHash is AES-128-CBC (PKCS7) over "k=v&k=v&...", keyed by the
merchant's two APG AES keys (Key1 = key, Key2 = IV) and base64-encoded. The
exact field set and their order come from the merchant's APG sample code;
HS_HASH_FIELDS / SSO_HASH_FIELDS below are the order used here and are the
first thing to check if APG answers "Invalid Request". The key encoding
(utf8 / base64 / hex) is likewise per merchant - see kamra_apg_key_encoding.
"""

import base64
import binascii
import json
import re
import time
from urllib.parse import parse_qs, quote, urlparse

import frappe
from frappe.utils import get_url

GATEWAY = "APG"

# Hosts from the guide's "How to Go Live" (sandbox vs production).
SANDBOX_HOST = "https://sandbox.bankalfalah.com"
LIVE_HOST = "https://payments.bankalfalah.com"

# Page-redirection channel is 1001 (1002 is the API channel). Transaction type
# 3 = credit/debit card; 1 = Alfa Wallet, 2 = Alfalah bank account. The guest
# can pick another method on APG's own page, so this is only APG's default.
CHANNEL_ID = "1001"
CARD_TRANSACTION_TYPE = "3"
# The handshake returns the AuthToken in its JSON response when
# HS_IsRedirectionRequest is "0" - verified against the APG sandbox. With "1"
# APG skips the JSON body and 302s the caller to HS_ReturnURL instead (the
# browser-redirect variant of the flow), which is not what a server-to-server
# handshake wants.
HS_JSON_MODE = "0"

# Kamra's partner referral link: costs the hotel nothing, helps fund the
# project. Site config kamra_apg_signup_url points it elsewhere.
SIGNUP_URL = "https://www.bankalfalah.com/digital-banking/alfa-payment-gateway/"

# The fields, in order, that make up each RequestHash.
HS_HASH_FIELDS = (
	"HS_ChannelId", "HS_IsRedirectionRequest", "HS_ReturnURL", "HS_MerchantId",
	"HS_StoreId", "HS_MerchantHash", "HS_MerchantUsername",
	"HS_MerchantPassword", "HS_TransactionReferenceNumber",
)
SSO_HASH_FIELDS = (
	"AuthToken", "ChannelId", "Currency", "ReturnURL", "MerchantId",
	"StoreId", "MerchantHash", "MerchantUsername", "MerchantPassword",
	"TransactionTypeId", "TransactionReferenceNumber", "TransactionAmount",
)


def _require_credentials(settings):
	"""Fail at link time with something the desk can act on, rather than at
	the guest's first click."""
	missing = [label for field, label in (
		("apg_merchant_id", "Merchant ID"),
		("apg_store_id", "Store ID"),
		("apg_merchant_hash", "Merchant hash"),
		("apg_merchant_username", "Merchant username"),
		("apg_merchant_password", "Merchant password"),
		("apg_key1", "AES Key 1"),
		("apg_key2", "AES Key 2"),
	) if not _secret(settings, field)]
	if missing:
		frappe.throw("APG needs its Bank Alfalah credentials: "
		             + ", ".join(missing) + ".")


def _secret(settings, field: str) -> str:
	"""A credential off the settings doc: get_password decrypts a Password
	field and returns a Data field as-is. Only ever pass a Data or Password
	fieldname - Frappe's get_password trips over a Check."""
	return settings.get_password(field, raise_exception=False) or ""


def _host(settings) -> str:
	return (frappe.conf.get("kamra_apg_host") or
	        (SANDBOX_HOST if settings.apg_sandbox else LIVE_HOST)).rstrip("/")


def _hs_url(settings) -> str:
	return frappe.conf.get("kamra_apg_hs_url") or f"{_host(settings)}/HS/HS/HS"


def _sso_url(settings) -> str:
	return frappe.conf.get("kamra_apg_sso_url") or f"{_host(settings)}/SSO/SSO/SSO"


def order_status_url(settings, reference: str) -> str:
	"""The IPN OrderStatus URL for one order: merchant + store + order ref."""
	override = frappe.conf.get("kamra_apg_order_status_url")
	if override:
		return (f"{override.rstrip('/')}/{_secret(settings, 'apg_merchant_id')}"
		        f"/{_secret(settings, 'apg_store_id')}/{quote(reference)}")
	return (f"{_host(settings)}/HS/api/IPN/OrderStatus"
	        f"/{_secret(settings, 'apg_merchant_id')}"
	        f"/{_secret(settings, 'apg_store_id')}/{quote(reference)}")


# ── RequestHash: AES-128-CBC(PKCS7), key = AES Key1, IV = AES Key2 ───────

def _decode_key(value: str) -> bytes:
	encoding = (frappe.conf.get("kamra_apg_key_encoding") or "utf8").lower()
	if encoding == "base64":
		try:
			return base64.b64decode(value)
		except (binascii.Error, ValueError):
			pass
	elif encoding == "hex":
		try:
			return binascii.unhexlify(value)
		except (binascii.Error, ValueError):
			pass
	return value.encode()


def _key16(value: str) -> bytes:
	"""APG's keys are 16 bytes; tolerate a longer or shorter one the way the
	reference implementation does - truncate, or pad with NUL."""
	raw = _decode_key(value)
	return (raw + b"\x00" * 16)[:16]


def _plaintext(fields: dict, order) -> str:
	return "&".join(f"{k}={fields.get(k) or ''}" for k in order)


def request_hash(settings, fields: dict, order) -> str:
	from cryptography.hazmat.primitives import padding
	from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

	padder = padding.PKCS7(128).padder()
	data = padder.update(_plaintext(fields, order).encode()) + padder.finalize()
	cipher = Cipher(algorithms.AES(_key16(_secret(settings, "apg_key1"))),
	                modes.CBC(_key16(_secret(settings, "apg_key2"))))
	encryptor = cipher.encryptor()
	return base64.b64encode(encryptor.update(data) + encryptor.finalize()).decode()


def _amount_text(amount) -> str:
	value = float(amount or 0)
	return str(int(value)) if value == int(value) else f"{value:.2f}"


def _loads(text):
	"""Parse JSON, unwrapping the double encoding APG sometimes uses: its
	OrderStatus endpoint returns a JSON *string* holding the JSON object."""
	try:
		value = json.loads(text)
	except (TypeError, ValueError):
		return None
	if isinstance(value, str):
		try:
			value = json.loads(value)
		except (TypeError, ValueError):
			return None
	return value


def _json_body(resp) -> dict:
	value = _loads(resp.text or "")
	return value if isinstance(value, dict) else {}


def _describe(resp) -> str:
	"""What APG actually answered, so a failed handshake is diagnosable from
	the Error Log rather than a bare "no auth token"."""
	bits = [f"HTTP {resp.status_code}", str(resp.headers.get("content-type") or "")]
	if resp.headers.get("location"):
		bits.append(f"-> {resp.headers['location']}")
	snippet = " ".join((resp.text or "").split())[:300]
	if snippet:
		bits.append(f"| {snippet}")
	return " ".join(b for b in bits if b)


# ── the two-step handshake (used by www/apg_checkout) ────────────────────

def _merchant_fields(settings) -> dict:
	return {
		"HS_MerchantId": _secret(settings, "apg_merchant_id"),
		"HS_StoreId": _secret(settings, "apg_store_id"),
		"HS_MerchantHash": _secret(settings, "apg_merchant_hash"),
		"HS_MerchantUsername": _secret(settings, "apg_merchant_username"),
		"HS_MerchantPassword": _secret(settings, "apg_merchant_password"),
	}


def handshake(settings, *, amount, currency: str, reference: str,
              return_url: str) -> tuple[str, str, dict]:
	"""Step 1 and the Step-2 field set, in one place. Returns
	(auth_token, sso_url, sso_fields) - the caller renders sso_fields as a
	form that POSTs to sso_url."""
	import requests

	_require_credentials(settings)
	hs = {
		"HS_ChannelId": CHANNEL_ID,
		"HS_IsRedirectionRequest": HS_JSON_MODE,
		"HS_ReturnURL": return_url,
		**_merchant_fields(settings),
		"HS_TransactionReferenceNumber": reference,
	}
	hs["HS_RequestHash"] = request_hash(settings, hs, HS_HASH_FIELDS)

	# never follow a redirect here: in the wrong mode APG 302s to the return
	# URL, and quietly chasing that turns a config error into a page of HTML
	resp = requests.post(_hs_url(settings), data=hs, timeout=30,
	                     allow_redirects=False)
	data = _json_body(resp)
	if str(data.get("success")).lower() != "true" or not data.get("AuthToken"):
		frappe.throw("APG refused the handshake: "
		             + (data.get("ErrorMessage") or _describe(resp)))

	sso = {
		"AuthToken": data["AuthToken"],
		"ChannelId": CHANNEL_ID,
		"Currency": currency,
		"ReturnURL": return_url,
		"TransactionTypeId": CARD_TRANSACTION_TYPE,
		"TransactionReferenceNumber": reference,
		"TransactionAmount": _amount_text(amount),
		"MerchantId": hs["HS_MerchantId"],
		"StoreId": hs["HS_StoreId"],
		"MerchantHash": hs["HS_MerchantHash"],
		"MerchantUsername": hs["HS_MerchantUsername"],
		"MerchantPassword": hs["HS_MerchantPassword"],
	}
	sso["RequestHash"] = request_hash(settings, sso, SSO_HASH_FIELDS)
	return data["AuthToken"], _sso_url(settings), sso


def order_status(settings, reference: str) -> dict:
	"""The authoritative answer on whether an order was paid."""
	import requests

	resp = requests.get(order_status_url(settings, reference), timeout=20)
	if resp.status_code >= 400:
		frappe.throw(f"APG order status lookup failed (HTTP {resp.status_code}).")
	return _parse_status(resp.text)


def _parse_status(text: str) -> dict:
	"""An order-status answer. Usually JSON (sometimes double-encoded as a
	JSON string); the guide's own samples show a JS-object-looking body
	({ ResponseCode = "00", ... }), so accept that too."""
	value = _loads(text)
	if isinstance(value, dict):
		return value
	return {m.group(1): (m.group(2) or "").strip()
	        for m in re.finditer(r'([A-Za-z_]+)\s*=\s*"?([^",}\n]*)"?', text or "")}


def _is_paid(status: dict) -> bool:
	return (str(status.get("ResponseCode") or "").strip() == "00"
	        and str(status.get("TransactionStatus") or "").strip().lower() == "paid")


# ── the seam's provider contract ─────────────────────────────────────────

def _reference(reference: str) -> str:
	"""A unique, URL-safe order reference per link creation - APG rejects a
	reference reused across orders, and a folio can be re-linked."""
	slug = re.sub(r"[^A-Za-z0-9]", "", reference or "")[:24] or "KAMRA"
	return f"{slug}{int(time.time())}"[:40]


def create_link(settings, *, amount: float, currency: str, reference: str,
                description: str, customer: dict, notes: dict) -> tuple[str, str]:
	"""Returns (link id, url). APG has no server-side link object, so the link
	is a Kamra page that runs the handshake when the guest opens it; the link
	id is the order reference APG will echo back on every callback."""
	_require_credentials(settings)
	link_id = _reference(reference)
	return link_id, checkout_url(link_id)


def checkout_url(reference: str) -> str:
	return f"{get_url('/apg_checkout')}?ref={quote(reference)}"


def test_link(link_id: str) -> str:
	return f"{get_url('/apg_checkout')}?test=1&ref={quote(link_id)}"


def info() -> dict:
	return {
		"gateway": GATEWAY,
		"webhook_url": get_url("/api/method/kamra.payments.apg_webhook"),
		"signup_url": frappe.conf.get("kamra_apg_signup_url") or SIGNUP_URL,
		"needs_webhook": True,
	}


def order_reference(payload: bytes) -> str | None:
	"""The order reference APG echoes back - from the IPN listener body
	(url=.../OrderStatus/{mid}/{sid}/{ref}) or an O=<ref> post."""
	text = (payload or b"").decode("utf-8", "replace").strip()
	if not text:
		return None
	qs = parse_qs(text)
	target = (qs.get("url") or [None])[0]
	if target:
		return urlparse(target).path.rstrip("/").rsplit("/", 1)[-1] or None
	if qs.get("O"):
		return qs["O"][0]
	body = _loads(text)
	if isinstance(body, dict):
		if body.get("url"):
			return urlparse(str(body["url"])).path.rstrip("/").rsplit("/", 1)[-1] or None
		if body.get("O"):
			return str(body["O"])
	return None


def webhook_folio(payload: bytes) -> str | None:
	ref = order_reference(payload)
	if not ref:
		return None
	return frappe.db.get_value("Folio", {"payment_link_id": ref}, "name")


def verify_webhook(settings, payload: bytes, headers: dict) -> dict | None:
	"""APG signs nothing, so trust comes from asking APG: the status lookup is
	built from the property's own credentials, never from the caller's URL, so
	a forged body can only name an order, not change the answer."""
	ref = order_reference(payload)
	if not ref:
		return None
	status = order_status(settings, ref)
	if not _is_paid(status):
		return None
	return {"link_id": ref,
	        "amount": float(status.get("TransactionAmount") or 0)}
