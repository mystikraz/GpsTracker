"""Email delivery abstraction; manual links are the safe development default."""

from __future__ import annotations

import logging
import smtplib
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Protocol


class EmailProvider(Protocol):
    def send(self, *, recipient: str, subject: str, body: str) -> None: ...


@dataclass(frozen=True, slots=True)
class ManualLinkProvider:
    """Returns content to the authorized API caller; caller must no-store it."""

    def send(self, *, recipient: str, subject: str, body: str) -> str:
        del recipient, subject
        return body


@dataclass(frozen=True, slots=True)
class SmtpProvider:
    host: str
    port: int
    sender: str
    starttls: bool = True

    def send(self, *, recipient: str, subject: str, body: str) -> None:
        message = EmailMessage()
        message["From"] = self.sender
        message["To"] = recipient
        message["Subject"] = subject
        message.set_content(body)
        with smtplib.SMTP(self.host, self.port, timeout=10) as client:
            if self.starttls:
                client.starttls()
            client.send_message(message)


class SesProvider:
    """SES adapter boundary; AWS client wiring is intentionally injected later."""

    def __init__(self, client, sender: str) -> None:
        self.client = client
        self.sender = sender

    def send(self, *, recipient: str, subject: str, body: str) -> None:
        self.client.send_email(
            Source=self.sender,
            Destination={"ToAddresses": [recipient]},
            Message={"Subject": {"Data": subject}, "Body": {"Text": {"Data": body}}},
        )

