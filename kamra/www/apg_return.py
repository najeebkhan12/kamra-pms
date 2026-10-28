"""Where APG returns the guest after paying.

APG tells us only the order reference (?O=). Whether the money actually
arrived comes from APG's own OrderStatus API, which we check here and settle
the folio once (settle_payment_link is idempotent, so a retry or the IPN
listener posting the same payment changes nothing).
"""

import frappe
from frappe import _

no_cache = 1


def get_context(context):
	context.no_cache = 1
	context.ok = False
	context.message = None

	ref = (frappe.request.args.get("O") or "").strip()
	if not ref:
		# a bare handshake callback (auth_token) is not a payment
		context.message = _("We could not match this to a payment.")
		return context

	folio_name = frappe.db.get_value("Folio", {"payment_link_id": ref}, "name")
	if not folio_name:
		context.message = _("This payment reference is no longer valid.")
		return context

	property = frappe.db.get_value("Folio", folio_name, "property")
	from kamra.payments import _settings, settle_payment_link
	try:
		settings = _settings(property)
	except Exception:
		context.message = _("Online payment is not set up for this property.")
		return context
	if settings.gateway != "APG":
		context.message = _("This property does not take payments through APG.")
		return context

	from kamra.localization.pakistan import alfa
	try:
		status = alfa.order_status(settings, ref)
	except Exception as exc:
		frappe.log_error(title="APG order status failed", message=str(exc))
		context.message = _("We could not confirm the payment just now. "
		                    "The hotel will check and settle your folio.")
		return context

	if alfa._is_paid(status):
		settle_payment_link(folio_name, ref,
		                    float(status.get("TransactionAmount") or 0))
		context.ok = True
		context.message = _("Thank you - your payment has been received.")
	else:
		context.message = _("Your payment was not completed. You can try "
		                    "again from the link, or pay at the desk.")
	return context
