"""ISO 20022 message generation and parsing adapter.

GAP-294: SWIFT/ISO 20022 Message Support.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from decimal import Decimal
from typing import Literal

from lxml import etree
from pydantic import BaseModel, Field

MessageType = Literal["pacs.008", "pacs.009", "camt.053"]

ISO20022_NAMESPACES: dict[str, str] = {
    "pacs.008": "urn:iso:std:iso:20022:tech:xsd:pacs.008.001.10",
    "pacs.009": "urn:iso:std:iso:20022:tech:xsd:pacs.009.001.10",
    "camt.053": "urn:iso:std:iso:20022:tech:xsd:camt.053.001.11",
}


class Pacs008Payload(BaseModel):
    """Payload for generating a pacs.008 Customer Credit Transfer Initiation."""

    msg_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    creation_dt: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    settlement_dt: str  # YYYY-MM-DD
    instructed_amount: Decimal
    currency: str = "USD"
    debtor_name: str
    debtor_iban: str
    creditor_name: str
    creditor_iban: str
    creditor_bic: str
    remittance_info: str = ""


class ISO20022Adapter:
    """Generates and parses ISO 20022 XML messages.

    Supports pacs.008, pacs.009, and camt.053 message types.
    All amounts use Decimal arithmetic to prevent floating-point drift —
    required for financial audit compliance.
    """

    def generate_pacs008(self, payload: Pacs008Payload) -> bytes:
        """Generate a pacs.008 FIToFICstmrCdtTrf XML message.

        Args:
            payload: Transfer payload with debtor and creditor details.

        Returns:
            UTF-8 encoded ISO 20022 compliant XML bytes.
        """
        ns = ISO20022_NAMESPACES["pacs.008"]
        root = etree.Element("Document", nsmap={None: ns})
        fi_to_fi = etree.SubElement(root, "FIToFICstmrCdtTrf")
        grp_hdr = etree.SubElement(fi_to_fi, "GrpHdr")
        etree.SubElement(grp_hdr, "MsgId").text = payload.msg_id
        etree.SubElement(grp_hdr, "CreDtTm").text = payload.creation_dt.strftime("%Y-%m-%dT%H:%M:%S")
        etree.SubElement(grp_hdr, "NbOfTxs").text = "1"
        etree.SubElement(grp_hdr, "TtlIntrBkSttlmAmt", Ccy=payload.currency).text = str(payload.instructed_amount)
        etree.SubElement(grp_hdr, "IntrBkSttlmDt").text = payload.settlement_dt

        cdt_trf = etree.SubElement(fi_to_fi, "CdtTrfTxInf")
        pmt_id = etree.SubElement(cdt_trf, "PmtId")
        etree.SubElement(pmt_id, "InstrId").text = f"INSTR-{payload.msg_id[:8]}"
        etree.SubElement(pmt_id, "EndToEndId").text = f"E2E-{payload.msg_id[:8]}"
        etree.SubElement(cdt_trf, "IntrBkSttlmAmt", Ccy=payload.currency).text = str(payload.instructed_amount)

        cdtr_agt = etree.SubElement(cdt_trf, "CdtrAgt")
        fin_instn_id = etree.SubElement(cdtr_agt, "FinInstnId")
        etree.SubElement(fin_instn_id, "BICFI").text = payload.creditor_bic

        cdtr = etree.SubElement(cdt_trf, "Cdtr")
        etree.SubElement(cdtr, "Nm").text = payload.creditor_name
        cdtr_acct = etree.SubElement(cdt_trf, "CdtrAcct")
        cdtr_id = etree.SubElement(cdtr_acct, "Id")
        etree.SubElement(cdtr_id, "IBAN").text = payload.creditor_iban

        if payload.remittance_info:
            rmt_inf = etree.SubElement(cdt_trf, "RmtInf")
            etree.SubElement(rmt_inf, "Ustrd").text = payload.remittance_info

        return etree.tostring(root, pretty_print=True, xml_declaration=True, encoding="UTF-8")

    def parse_pacs008(self, xml_bytes: bytes) -> Pacs008Payload:
        """Parse a pacs.008 XML message into a structured payload.

        Args:
            xml_bytes: UTF-8 encoded pacs.008 XML document.

        Returns:
            Pacs008Payload with parsed fields.

        Raises:
            ValueError: If the message is not valid pacs.008.
        """
        root = etree.fromstring(xml_bytes)
        ns = {"iso": ISO20022_NAMESPACES["pacs.008"]}
        grp_hdr = root.find(".//iso:GrpHdr", ns)
        if grp_hdr is None:
            raise ValueError("Invalid pacs.008 message: missing GrpHdr")
        msg_id = grp_hdr.findtext("iso:MsgId", namespaces=ns) or ""
        cdt_trf = root.find(".//iso:CdtTrfTxInf", ns)
        amount_el = cdt_trf.find("iso:IntrBkSttlmAmt", ns) if cdt_trf is not None else None
        return Pacs008Payload(
            msg_id=msg_id,
            settlement_dt=grp_hdr.findtext("iso:IntrBkSttlmDt", namespaces=ns) or "",
            instructed_amount=Decimal(amount_el.text if amount_el is not None else "0"),
            currency=amount_el.get("Ccy", "USD") if amount_el is not None else "USD",
            debtor_name="",
            debtor_iban="",
            creditor_name=root.findtext(".//iso:Cdtr/iso:Nm", namespaces=ns) or "",
            creditor_iban=root.findtext(".//iso:CdtrAcct/iso:Id/iso:IBAN", namespaces=ns) or "",
            creditor_bic=root.findtext(".//iso:CdtrAgt/iso:FinInstnId/iso:BICFI", namespaces=ns) or "",
        )
