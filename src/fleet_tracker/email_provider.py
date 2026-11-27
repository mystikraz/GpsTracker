"""Email delivery abstraction; manual links are the safe development default."""

from __future__ import annotations

import logging
import json
import smtplib
from urllib import error, request
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Protocol


class EmailProvider(Protocol):
    def send(self, *, recipient: str, subject: str, body: str) -> None: ...


class EmailDeliveryError(RuntimeError):
    """Raised when an email provider rejects or cannot deliver a message."""


@dataclass(frozen=True, slots=True)
class ResendProvider:
    api_key: str
    sender: str

    def send(self, *, recipient: str, subject: str, body: str) -> None:
        payload = json.dumps({"from": self.sender, "to": [recipient], "subject": subject, "html": body}).encode("utf-8")
        req = request.Request(
            "https://api.resend.com/emails",
            data=payload,
            headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=10) as response:
                if response.status < 200 or response.status >= 300:
                    raise EmailDeliveryError("email provider rejected the message")
        except (error.HTTPError, error.URLError, TimeoutError, OSError) as exc:
            raise EmailDeliveryError("email provider request failed") from exc


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

