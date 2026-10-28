"""The desk's APG payment link lands here.

APG is a redirect gateway: rather than handing the guest a gateway-hosted
link, we run the first handshake step with the property's own APG keys and
post the guest straight on to APG's secure checkout (step two). The amount is
read from the folio, never from the query string, so a link cannot be edited
to change what is charged.
"""

import frappe
from frappe import _
from frappe.utils import flt, get_url

no_cache = 1


def get_context(context):
	context.no_cache = 1
	context.error = None
	context.test_mode = False
	context.form_url = None
	context.fields = {}

	ref = (frappe.request.args.get("ref") or "").strip()
	if not ref:
		context.error = _("This payment link is incomplete.")
		return context
	folio_name = frappe.db.get_value("Folio", {"payment_link_id": ref}, "name")
	if not folio_name:
		context.error = _("This payment link is no longer valid. Ask the hotel for a new one.")
		return context

	folio = frappe.get_doc("Folio", folio_name)
	amount = flt(folio.payment_link_amount)
	if amount <= 0:
		context.error = _("Nothing is due on this booking.")
		return context

	from kamra.payments import _settings
	try:
		settings = _settings(folio.property)
	except Exception:
		context.error = _("Online payment is not set up for this property. Please pay at the desk.")
		return context
	if settings.gateway != "APG":
		context.error = _("This property does not take payments through APG.")
		return context

	if settings.test_mode or frappe.request.args.get("test") == "1":
		context.test_mode = True
		return context

	currency = (frappe.db.get_value("Property", folio.property, "currency")
	            or "PKR")
	try:
		from kamra.localization.pakistan import alfa
		_auth, url, fields = alfa.handshake(
			settings, amount=amount, currency=currency, reference=ref,
			return_url=get_url("/apg_return"))
	except Exception as exc:
		frappe.log_error(title="APG handshake failed", message=str(exc))
		context.error = _("We could not reach the payment gateway. "
		                  "Please try again or pay at the desk." + str(exc))
		return context

	context.form_url = url
	context.fields = fields
	return context
