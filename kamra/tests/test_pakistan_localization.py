"""The Pakistan country pack: PKR, provincial Sales Tax, CNIC, APG.

Pure assertions on the pack's contract, plus one integration check that a
property created for Pakistan really gets the currency and clock the pack
declares."""

import unittest
from decimal import Decimal

import frappe

from kamra import localization as loc
from kamra.localization import pakistan


class TestPakistanPack(unittest.TestCase):
	def test_registered_in_the_hook(self):
		# get_hooks returns each hook value as a list of dotted paths
		self.assertEqual(
			(frappe.get_hooks("kamra_localization") or {}).get("Pakistan"),
			["kamra.localization.pakistan"])

	def test_country_resolves_to_the_pack(self):
		self.assertIs(loc.pack_for_country("Pakistan"), pakistan)

	def test_currency_and_locale(self):
		info = pakistan.locale(frappe._dict(name="P", currency="PKR"))
		self.assertEqual(info["currency_symbol"], "Rs ")
		self.assertEqual(info["locale"], "en-PK")
		self.assertEqual(info["currency"], "PKR")

	def test_invoice_is_sales_tax_not_gst(self):
		ctx = pakistan.invoice_context(frappe._dict(name="P", city="Karachi"))
		self.assertEqual(ctx["tax_label"], "Sales Tax")
		self.assertEqual(ctx["tax_id_label"], "NTN")
		# India's SAC codes and CGST/SGST split do not apply here
		self.assertIsNone(ctx["service_code"])
		self.assertIsNone(ctx["sac"])
		self.assertEqual(ctx["split"], [("tax", Decimal("1"))])
		self.assertEqual(ctx["place_of_supply"], "Karachi")

	def test_room_tax_is_flat_and_falls_back(self):
		self.assertEqual(
			pakistan.calculate_room_tax("P", frappe._dict(tax_percent=13), 90000),
			Decimal("13"))
		self.assertEqual(
			pakistan.calculate_room_tax("P", frappe._dict(tax_percent=0), 90000),
			pakistan.DEFAULT_SALES_TAX)

	def test_tax_rate_options_are_the_provincial_bands(self):
		rates = pakistan.tax_rate_options("P")
		self.assertEqual(rates, sorted(rates))
		self.assertIn(13, rates)  # Sindh (SRB)
		self.assertIn(16, rates)  # Punjab (PRA)

	def test_front_desk_vocabulary(self):
		self.assertIn("CNIC", loc.id_types(pakistan))
		self.assertNotIn("UPI", loc.payment_modes(pakistan))
		vocab = loc.front_desk_vocabulary(pakistan)
		self.assertEqual(vocab["default_nationality"], "Pakistani")
		self.assertTrue(loc.registration_card_required(pakistan))

	def test_offers_apg_only(self):
		self.assertEqual(loc.payment_gateways(pakistan), ["APG"])
		self.assertIs(pakistan.payment_provider("APG"), pakistan.alfa)

	def test_no_india_only_integrations(self):
		integ = loc.integrations(pakistan)
		self.assertEqual(integ["payment_gateways"], ["APG"])
		self.assertFalse(integ["tax_return"])
		self.assertFalse(integ["verify_tax_id"])
		self.assertFalse(integ["verify_guest_id"])

	def test_amount_in_words_uses_the_south_asian_scale(self):
		words = pakistan.amount_in_words(frappe._dict(currency="PKR"), 125000)
		self.assertEqual(words, "Rupees One Lakh Twenty Five Thousand Only")

	def test_nationality_and_notice_language(self):
		terms = loc.privacy_terms(pakistan)
		self.assertEqual(terms["notice_languages"], ["ur"])
		self.assertEqual(terms["adult_age"], 18)


class TestPakistanPropertySetup(unittest.TestCase):
	"""`country == "Pakistan"` must set the currency and time zone the way
	India does - the wizard's promise ("this sets currency, zone and tax")."""

	def test_country_defaults_from_the_pack(self):
		from kamra import api

		property_name = "UT Pakistan Pack"
		if frappe.db.exists("Property", property_name):
			frappe.delete_doc("Property", property_name, force=True,
			                  ignore_permissions=True)
		if not frappe.db.exists("Currency", "PKR"):
			frappe.get_doc({"doctype": "Currency", "currency_name": "PKR",
			                "symbol": "Rs", "enabled": 1}
			               ).insert(ignore_permissions=True)
		try:
			api.setup_property({"property": {"property_name": property_name,
			                                 "country": "Pakistan",
			                                 "city": "Karachi"}})
			prop = frappe.get_doc("Property", property_name)
			self.assertEqual(prop.currency, "PKR")
			self.assertEqual(prop.timezone, "Asia/Karachi")
		finally:
			if frappe.db.exists("Property", property_name):
				frappe.delete_doc("Property", property_name, force=True,
				                  ignore_permissions=True)
