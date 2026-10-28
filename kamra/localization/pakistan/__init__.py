"""Pakistan localization pack.

Hotel accommodation and hotel food & beverage are provincial **Sales Tax on
Services** supplies, not a federal GST: Punjab (PRA) ~16%, Sindh (SRB) ~13%,
Khyber Pakhtunkhwa (KPRA) ~15% and Balochistan (BRA) ~15%, with Islamabad
administered federally. Each province's Revenue Authority registers the hotel
and collects the tax, so the rate is the property's own flat provincial rate
rather than a slab:

  - the rate comes from the Room Type's tax percent; unset means the standard
    (DEFAULT_SALES_TAX)
  - the tax invoice must quote the hotel's National Tax Number (NTN; the
    sales tax registration number is the STRN)
  - single provincial "Sales Tax" line

Online card payments run through Bank Alfalah's Alfa Payment Gateway (APG);
the provider lives beside this pack in alfa.py.

Pakistan-only integrations sit in this package; the core reaches them only
through the hooks in kamra/localization/__init__.py.
"""

from decimal import Decimal

import frappe

# Punjab (PRA) standard rate - the fallback when a Room Type sets none.
# Sindh (SRB) is ~13%, KP (KPRA) and Balochistan (BRA) ~15%.
DEFAULT_SALES_TAX = Decimal("16")

DEFAULT_CURRENCY = "PKR"
DEFAULT_TIMEZONE = "Asia/Karachi"
DEFAULT_NATIONALITY = "Pakistani"
# named in the guest privacy notice (the Personal Data Protection Bill is
# not yet enacted, so there is no single national authority to name)
PRIVACY_AUTHORITY = "your provincial data protection authority"
GUEST_REPORT = "for foreign nationals, guest registration with the police"
# what the front desk records: citizens carry the CNIC, visitors a passport
ID_TYPES = ["CNIC", "Passport", "Driving License", "Other"]
#cards and bank transfer (Raast) are the online rails
PAYMENT_MODES = ["Cash", "Card", "Bank Transfer"]
# Pakistani hotels keep a signed registration card (the register the police
# may inspect), so the guided check-in makes the GRC a required step by
# default. A property can still change it in its check-in steps.
REGISTRATION_CARD_REQUIRED = True
# Urdu is the national language; the guest privacy notice is offered in it
# (frontend/src/i18n/notice/ur.json)
NOTICE_LANGUAGES = ["ur"]


def calculate_room_tax(property, room_type_doc, nightly_rate) -> Decimal:
	"""Sales tax on one room night - the property's provincial rate (the Room
	Type's tax percent), or the standard rate when the room type sets none."""
	v = room_type_doc.get("tax_percent") if room_type_doc else None
	return Decimal(str(v)) if v else DEFAULT_SALES_TAX


def fnb_tax_rate(property) -> float:
	"""Hotel restaurants are the same provincial sales-tax supply."""
	rates = frappe.get_all(
		"Room Type", filters={"property": property, "disabled": 0},
		pluck="tax_percent", limit=5)
	first = next((r for r in rates if r), None)
	return float(first) if first else float(DEFAULT_SALES_TAX)


def services_tax_rate(property) -> float:
	"""Laundry and other guest services carry the same provincial rate."""
	return fnb_tax_rate(property)


def tax_rate_options(property) -> list:
	"""The provincial bands a desk may pick from: SRB 13, KPRA/BRA 15,
	PRA 16, plus the higher rates notified for specific services."""
	return [0, 13, 15, 16, 17, 19.5, 20]


def invoice_context(prop_doc) -> dict:
	"""Country block for the invoice print."""
	return {
		"tax_label": "Sales Tax",
		"tax_id_label": "NTN",
		# Pakistan's sales tax on services is not a coded supply like India's
		# SAC, so no line carries a service code
		"service_code": None,
		"sac": None,
		"place_of_supply": prop_doc.get("city") or prop_doc.get("state"),
		# provincial sales tax, single line
		"split": [("tax", Decimal("1"))],
		"footer": "This is a computer-generated sales tax invoice.",
	}


def amount_in_words(prop_doc, amount) -> str:
	from kamra.localization.words import amount_in_words as spell

	# Pakistan groups numbers the South Asian way - lakh (10^5), crore (10^7)
	return spell(amount, prop_doc.get("currency") or DEFAULT_CURRENCY,
	             indian=True)


def locale(prop_doc) -> dict:
	return {
		# trailing space: "Rs 1,500" - the UI concatenates symbol+amount
		"currency_symbol": "Rs ",
		"locale": "en-PK",
		"currency": prop_doc.get("currency") or DEFAULT_CURRENCY,
		"tax_label": "Sales Tax",
		"tax_id_label": "NTN",
		"tax_rates": tax_rate_options(prop_doc.name),
	}


# ── Pakistan-only integrations ───────────────────────────────────────────

PAYMENT_GATEWAYS = ["APG"]


def payment_provider(gateway: str):
	from kamra.localization.pakistan import alfa
	return alfa
