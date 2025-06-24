from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from app.core.config import settings
from typing import List
import logging

logger = logging.getLogger(__name__)

# Email configuration
conf = ConnectionConfig(
    MAIL_USERNAME=settings.MAIL_USERNAME,
    MAIL_PASSWORD=settings.MAIL_PASSWORD,
    MAIL_FROM=settings.MAIL_FROM,
    MAIL_PORT=settings.MAIL_PORT,
    MAIL_SERVER=settings.MAIL_SERVER,
    MAIL_STARTTLS=settings.MAIL_STARTTLS,
    MAIL_SSL_TLS=settings.MAIL_SSL_TLS,
    USE_CREDENTIALS=settings.USE_CREDENTIALS,
    VALIDATE_CERTS=settings.VALIDATE_CERTS
)

async def send_magic_link_email(email: str, magic_link: str, client_ip: str = None) -> bool:
    """Send magic link email to user's email."""
    try:
        # Simple and friendly plain text email
        ip_info = f"來自 IP：{client_ip}" if client_ip else "IP 未知"
        
        email_content = f"""
嗨！這是你的 HackIt 登入連結
有人（希望是你）想要登入你的帳號，{ip_info}
點這個連結就能登入：
{magic_link}

————————————————————————————————————————

一些提醒：
• 連結 15 分鐘後會過期
• 15 分鐘內可以重複使用
• 別把連結給別人哦

————————————————————————————————————————

如果不是你要登入的話，忽略這封信就好。

HackIt 系統
        """.strip()
        
        message = MessageSchema(
            subject="HackIt 登入連結",
            recipients=[email],
            body=email_content,
            subtype="plain"
        )
        
        fm = FastMail(conf)
        await fm.send_message(message)
        
        logger.info(f"Magic link email sent successfully to {email}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to send magic link email to {email}: {str(e)}")
        return False 