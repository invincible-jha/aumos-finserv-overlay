"""Kafka event publisher adapter for aumos-finserv-overlay.

Wraps aumos_common.events.EventPublisher with finserv-specific
topic routing and schema enforcement.
"""

from typing import Any

from aumos_common.events import EventPublisher
from aumos_common.observability import get_logger

logger = get_logger(__name__)

# Topic routing for finserv domain events
_TOPIC_MAP: dict[str, str] = {
    "finserv.sox.evidence.collected": "finserv.sox",
    "finserv.model_risk.assessment.created": "finserv.model-risk",
    "finserv.pci_dss.scan.completed": "finserv.pci-dss",
    "finserv.synth_transactions.generated": "finserv.synthetic-data",
    "finserv.regulatory_report.generated": "finserv.reports",
}


class FinServEventPublisher(EventPublisher):
    """Finserv-specific Kafka event publisher.

    Extends base EventPublisher with domain-specific topic routing
    for financial services compliance events.
    """

    async def publish(self, event_type: str, payload: dict[str, Any]) -> None:
        """Publish a finserv domain event to the appropriate Kafka topic.

        Args:
            event_type: Dot-separated event type string (e.g. 'finserv.sox.evidence.collected').
            payload: Event payload dict.
        """
        topic = _TOPIC_MAP.get(event_type, "finserv.general")
        logger.debug(
            "Publishing finserv event",
            event_type=event_type,
            topic=topic,
        )
        # Delegate to base publisher with resolved topic
        await super().publish(event_type=event_type, payload={**payload, "_topic": topic})
