import logging
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from smtplib import SMTP
from typing import Optional

from fastapi import BackgroundTasks
from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.core.config import EmailConfigSettings

logger = logging.getLogger("open_sesame_logger")

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "common" / "template"


class EmailServices:
    def __init__(self, config: EmailConfigSettings, background_tasks: BackgroundTasks):
        self.config = config
        self.background_tasks = background_tasks
        self.env = Environment(
            loader=FileSystemLoader(TEMPLATE_DIR),
            autoescape=select_autoescape(["html"]),
        )

    def _send_sync(
        self,
        email_to: str,
        subject: str,
        html_body: str,
        attachment: Optional[bytes] = None,
        attachment_filename: Optional[str] = None,
        email_cc: Optional[str] = None,
    ) -> None:
        message = MIMEMultipart("mixed")
        message["Subject"] = subject
        message["From"] = (
            f"{self.config.EMAILS_FROM_NAME} <{self.config.EMAILS_FROM_EMAIL}>"
        )
        message["To"] = email_to
        if email_cc:
            message["Cc"] = email_cc

        message.attach(MIMEText(html_body, "html"))

        if attachment and attachment_filename:
            part = MIMEApplication(attachment, Name=attachment_filename)
            part["Content-Disposition"] = (
                f'attachment; filename="{attachment_filename}"'
            )
            message.attach(part)

        recipients = [email_to] + ([email_cc] if email_cc else [])

        with SMTP(self.config.SMTP_HOST, self.config.SMTP_PORT) as server:
            if self.config.SMTP_TLS:
                server.starttls()
            # Local catch-all servers (Mailpit) accept mail without credentials.
            if self.config.SMTP_USER:
                server.login(self.config.SMTP_USER, self.config.SMTP_PASSWORD)
            server.sendmail(
                self.config.EMAILS_FROM_EMAIL, recipients, message.as_string()
            )

    def _send_and_log(
        self,
        email_to: str,
        subject: str,
        html_body: str,
        attachment: Optional[bytes] = None,
        attachment_filename: Optional[str] = None,
        email_cc: Optional[str] = None,
    ) -> None:
        try:
            self._send_sync(
                email_to, subject, html_body, attachment, attachment_filename, email_cc
            )
        except Exception:
            logger.exception("Failed to send email to %s", email_to)

    async def send_email(
        self,
        email_to: str,
        subject: str,
        html_template: str,
        template_body: dict,
        attachment: Optional[bytes] = None,
        attachment_filename: Optional[str] = None,
        email_cc: Optional[str] = None,
    ) -> None:
        html_body = self.env.get_template(html_template).render(**template_body)
        # Schedule chạy sau khi respose http — caller không cần đợi SMTP nửa
        # đồng thời ngăn luôn timing side-channel attack trên các endpoint auth
        # tránh lộ việc email có tồn tại trong db hay không thông qua thời gian phản hồi
        self.background_tasks.add_task(
            self._send_and_log,
            email_to,
            subject,
            html_body,
            attachment,
            attachment_filename,
            email_cc,
        )

    async def send_verify_email(self, email_to: str, otp_code: str) -> None:
        await self.send_email(
            email_to=email_to,
            subject="Verify your Open Sesame account",
            html_template="verify_account.html",
            template_body={"otp_code": otp_code},
        )

    async def send_reset_password_email(self, email_to: str, otp_code: str) -> None:
        await self.send_email(
            email_to=email_to,
            subject="Reset your Open Sesame password",
            html_template="reset_password.html",
            template_body={"otp_code": otp_code},
        )

    async def send_mfa_code(self, email_to: str, otp_code: str) -> None:
        await self.send_email(
            email_to=email_to,
            subject="Your Open Sesame sign-in code",
            html_template="mfa_code.html",
            template_body={"otp_code": otp_code},
        )

    async def send_mfa_setup_code(self, email_to: str, otp_code: str) -> None:
        await self.send_email(
            email_to=email_to,
            subject="Confirm two-factor authentication for Open Sesame",
            html_template="mfa_setup.html",
            template_body={"otp_code": otp_code},
        )

    async def send_mfa_disable_code(self, email_to: str, otp_code: str) -> None:
        await self.send_email(
            email_to=email_to,
            subject="Confirm turning off two-factor authentication for Open Sesame",
            html_template="mfa_disable.html",
            template_body={"otp_code": otp_code},
        )
