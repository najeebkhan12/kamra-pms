"""The APG (Bank Alfalah) provider: RequestHash, callbacks, link creation.

APG is a redirect gateway, so the "link" is a Kamra page and money is
confirmed by asking APG for the order's status - these tests pin the crypto,
the callback parsing and the paid/not-paid decision."""

import base64
import json
import unittest
from unittest.mock import patch

import frappe

from kamra.localization.pakistan import alfa


class _Response:
	"""Just the bits of a requests Response the provider reads."""

	def __init__(self, text, status=200, location=None):
		self.text = text
		self.status_code = status
		self.headers = {"location": location} if location else {}


class _Settings:
	"""A stand-in for Payment Gateway Settings: only the credential lookups
	the provider makes (get_password covers Data fields too)."""

	def __init__(self, **values):
		self._values = values
		self.apg_sandbox = values.get("apg_sandbox", 1)

	def get_password(self, field, raise_exception=False):
		return self._values.get(field)


def _settings(**extra):
	values = {
		"apg_merchant_id": "123", "apg_store_id": "000456",
		"apg_merchant_hash": "MH", "apg_merchant_username": "user",
		"apg_merchant_password": "pass",
		"apg_key1": "0123456789abcdef", "apg_key2": "fedcba9876543210",
	}
	values.update(extra)
	return _Settings(**values)


class TestRequestHash(unittest.TestCase):
	KEY = b"0123456789abcdef"
	IV = b"fedcba9876543210"

	def _decrypt(self, hashed):
		from cryptography.hazmat.primitives import padding
		from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

		raw = base64.b64decode(hashed)
		decryptor = Cipher(algorithms.AES(self.KEY), modes.CBC(self.IV)).decryptor()
		unpadder = padding.PKCS7(128).unpadder()
		return (unpadder.update(decryptor.update(raw) + decryptor.finalize())
		        + unpadder.finalize()).decode()

	def test_hash_is_aes128cbc_pkcs7_of_the_field_string(self):
		hashed = alfa.request_hash(_settings(), {"a": "1", "b": "two words"}, ("a", "b"))
		self.assertEqual(len(base64.b64decode(hashed)) % 16, 0)
		self.assertEqual(self._decrypt(hashed), "a=1&b=two words")

	def test_field_order_is_the_one_given(self):
		hashed = alfa.request_hash(_settings(), {"a": "1", "b": "2"}, ("b", "a"))
		self.assertEqual(self._decrypt(hashed), "b=2&a=1")

	def test_missing_field_reads_as_empty(self):
		self.assertEqual(alfa._plaintext({"a": "1"}, ("a", "zz")), "a=1&zz=")

	def test_key_is_padded_or_truncated_to_16_bytes(self):
		self.assertEqual(alfa._key16("short"), b"short" + b"\x00" * 11)
		self.assertEqual(alfa._key16("x" * 30), b"x" * 16)


class TestCallbacks(unittest.TestCase):
	def test_reference_from_the_ipn_listener_body(self):
		body = (b"url=https://sandbox.bankalfalah.com/HS/api/IPN/"
		        b"OrderStatus/123/000456/KAMRA99")
		self.assertEqual(alfa.order_reference(body), "KAMRA99")

	def test_reference_from_the_o_parameter(self):
		self.assertEqual(alfa.order_reference(b"O=A10&RC=00"), "A10")

	def test_reference_from_a_json_body(self):
		self.assertEqual(
			alfa.order_reference(
				b'{"url": "https://x/HS/api/IPN/OrderStatus/1/2/REF7"}'),
			"REF7")

	def test_no_reference(self):
		self.assertIsNone(alfa.order_reference(b""))
		self.assertIsNone(alfa.order_reference(b"hello there"))

	def test_order_status_url_carries_the_merchant_ids(self):
		url = alfa.order_status_url(_settings(), "REF1")
		self.assertTrue(url.startswith(
			"https://sandbox.bankalfalah.com/HS/api/IPN/OrderStatus/123/000456/"))
		self.assertTrue(url.endswith("REF1"))

	def test_live_host_when_not_sandbox(self):
		url = alfa.order_status_url(_settings(apg_sandbox=0), "R")
		self.assertTrue(url.startswith("https://payments.bankalfalah.com/"))

	def test_status_parses_json_and_apg_js_object(self):
		self.assertEqual(alfa._parse_status('{"ResponseCode": "00"}')["ResponseCode"], "00")
		out = alfa._parse_status(
			'{ ResponseCode = "00", Description = "Success", '
			'TransactionStatus = "Paid" }')
		self.assertEqual(out["ResponseCode"], "00")
		self.assertEqual(out["TransactionStatus"], "Paid")

	def test_is_paid(self):
		self.assertTrue(alfa._is_paid(
			{"ResponseCode": "00", "TransactionStatus": "Paid"}))
		self.assertFalse(alfa._is_paid(
			{"ResponseCode": "00", "TransactionStatus": "Failed"}))
		self.assertFalse(alfa._is_paid(
			{"ResponseCode": "31", "TransactionStatus": "Paid"}))


class TestVerifyWebhook(unittest.TestCase):
	def _run(self, status):
		with patch.object(alfa, "order_status", return_value=status):
			return alfa.verify_webhook(_settings(), b"O=REF1", {})

	def test_a_paid_order_settles(self):
		self.assertEqual(
			self._run({"ResponseCode": "00", "TransactionStatus": "Paid",
			           "TransactionAmount": "1500"}),
			{"link_id": "REF1", "amount": 1500.0})

	def test_a_failed_or_unpaid_order_is_ignored(self):
		self.assertIsNone(self._run(
			{"ResponseCode": "00", "TransactionStatus": "Failed"}))
		self.assertIsNone(self._run(
			{"ResponseCode": "31", "TransactionStatus": "Paid"}))

	def test_a_body_with_no_reference_is_ignored(self):
		with patch.object(alfa, "order_status") as lookup:
			self.assertIsNone(alfa.verify_webhook(_settings(), b"", {}))
		lookup.assert_not_called()


class TestLinkCreation(unittest.TestCase):
	def test_the_link_is_the_hosted_checkout_page(self):
		link_id, url = alfa.create_link(
			_settings(), amount=500, currency="PKR", reference="FOLIO-0001",
			description="Stay", customer={}, notes={})
		self.assertTrue(link_id.startswith("FOLIO0001"))
		self.assertIn("/apg_checkout?ref=", url)
		self.assertTrue(url.endswith(link_id))

	def test_credentials_are_required(self):
		with self.assertRaises(frappe.ValidationError):
			alfa.create_link(_Settings(), amount=1, currency="PKR",
			                 reference="F", description="", customer={}, notes={})

	def test_amount_text_drops_a_whole_number_decimal(self):
		self.assertEqual(alfa._amount_text(1500), "1500")
		self.assertEqual(alfa._amount_text(1500.5), "1500.50")


class TestWebhookFolioLookup(unittest.TestCase):
	def test_an_unknown_reference_matches_no_folio(self):
		self.assertIsNone(alfa.webhook_folio(b"O=NOPE-NOT-A-REAL-LINK-REF"))


class TestResponseFormats(unittest.TestCase):
	"""APG's actual reply shapes. Both of these were failures against the
	sandbox: the wrong handshake mode returns HTML instead of JSON, and the
	order-status answer arrives double-encoded."""

	def test_handshake_asks_for_the_json_answer(self):
		# "1" makes APG 302 the caller to HS_ReturnURL instead of returning
		# the AuthToken, so the server-to-server handshake needs "0"
		self.assertEqual(alfa.HS_JSON_MODE, "0")

	def test_handshake_body_carries_that_mode(self):
		fields = {"HS_ChannelId": alfa.CHANNEL_ID, "HS_IsRedirectionRequest": alfa.HS_JSON_MODE}
		self.assertIn("HS_IsRedirectionRequest=0", alfa._plaintext(fields, ("HS_IsRedirectionRequest",)))

	def test_json_body_unwraps_a_double_encoded_handshake(self):
		body = json.dumps(json.dumps({"success": "true", "AuthToken": "tok"}))
		self.assertEqual(alfa._json_body(_Response(body)),
		                 {"success": "true", "AuthToken": "tok"})

	def test_status_parses_a_double_encoded_order_status(self):
		inner = {"ResponseCode": "00", "TransactionStatus": "Paid",
		         "TransactionAmount": "1500"}
		out = alfa._parse_status(json.dumps(json.dumps(inner)))
		self.assertEqual(out["ResponseCode"], "00")
		self.assertTrue(alfa._is_paid(out))

	def test_an_order_not_found_is_not_paid(self):
		inner = {"ResponseCode": "11", "Description": "Order Not Found",
		         "TransactionStatus": None}
		self.assertFalse(alfa._is_paid(alfa._parse_status(json.dumps(json.dumps(inner)))))

	def test_describe_reports_what_the_gateway_answered(self):
		text = alfa._describe(_Response("<html>Object moved</html>", status=302,
		                                location="https://example.org/back"))
		self.assertIn("302", text)
		self.assertIn("https://example.org/back", text)

	def test_json_body_falls_back_to_empty_on_html(self):
		self.assertEqual(alfa._json_body(_Response("<html>nope</html>")), {})
