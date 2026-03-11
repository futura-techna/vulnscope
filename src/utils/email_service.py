"""
VulnScope - Email Service
Handles sending emails for verification, password reset, and notifications
Supports Resend API (recommended for Render) and SMTP (local development)
"""

import logging
from typing import Optional
from jinja2 import Template

from src.config.settings import get_settings


logger = logging.getLogger(__name__)


class EmailService:
    """Service for sending emails via Resend API or SMTP"""
    
    def __init__(self):
        self.settings = get_settings()
        self.email_config = self.settings.email
    
    def _send_email_resend(self, to_email: str, subject: str, html_body: str, text_body: str) -> bool:
        """Send email using Resend API (works on Render)"""
        import requests
        
        if not self.email_config.resend_api_key:
            logger.error("Resend API key not configured")
            return False
        
        try:
            from_email = self.email_config.from_email or "onboarding@resend.dev"
            
            response = requests.post(
                "https://api.resend.com/emails",
                headers={
                    "Authorization": f"Bearer {self.email_config.resend_api_key}",
                    "Content-Type": "application/json"
                },
                json={
                    "from": f"{self.email_config.from_name} <{from_email}>",
                    "to": [to_email],
                    "subject": subject,
                    "html": html_body,
                    "text": text_body
                },
                timeout=30
            )
            
            if response.status_code == 200:
                logger.info(f"Email sent successfully to {to_email} via Resend")
                return True
            else:
                logger.error(f"Resend API error: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to send email via Resend to {to_email}: {e}")
            return False
    
    def _send_email_smtp(self, to_email: str, subject: str, html_body: str, text_body: str) -> bool:
        """Send email using SMTP (may not work on Render free tier)"""
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        
        if not self.email_config.smtp_user or not self.email_config.smtp_password:
            logger.error("SMTP credentials not configured")
            return False
        
        try:
            smtp = smtplib.SMTP(
                self.email_config.smtp_host,
                self.email_config.smtp_port,
                timeout=30
            )
            
            if self.email_config.smtp_use_tls:
                smtp.starttls()
            
            smtp.login(
                self.email_config.smtp_user,
                self.email_config.smtp_password
            )
            
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = f"{self.email_config.from_name} <{self.email_config.from_email or self.email_config.smtp_user}>"
            msg['To'] = to_email
            
            msg.attach(MIMEText(text_body, 'plain'))
            msg.attach(MIMEText(html_body, 'html'))
            
            smtp.sendmail(
                self.email_config.from_email or self.email_config.smtp_user,
                to_email,
                msg.as_string()
            )
            
            smtp.quit()
            logger.info(f"Email sent successfully to {to_email} via SMTP")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email via SMTP to {to_email}: {e}")
            return False
    
    def _send_email(self, to_email: str, subject: str, html_body: str, text_body: str) -> bool:
        """Send an email using configured provider"""
        logger.info(f"[Email] Attempting to send email to {to_email}: {subject}")
        logger.info(f"[Email] Email enabled: {self.email_config.enabled}, Provider: {self.email_config.provider}")
        
        if not self.email_config.enabled:
            logger.warning(f"[Email] Email sending is DISABLED. Email would have been sent to {to_email}: {subject}")
            logger.info(f"[Email] To enable emails, set VULNSCOPE_EMAIL__ENABLED=true and configure a provider (resend/smtp)")
            return False
        
        provider = self.email_config.provider.lower()
        
        if provider == 'resend':
            logger.info(f"[Email] Using Resend provider for {to_email}")
            return self._send_email_resend(to_email, subject, html_body, text_body)
        else:
            logger.info(f"[Email] Using SMTP provider for {to_email}")
            return self._send_email_smtp(to_email, subject, html_body, text_body)
    
    def send_verification_email(self, email: str, token: str, username: str) -> bool:
        """Send email verification link"""
        verification_url = f"{self.email_config.frontend_url}/verify-email?token={token}"
        
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
                .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
                .button { display: inline-block; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; margin: 20px 0; }
                .footer { text-align: center; color: #666; font-size: 12px; margin-top: 20px; }
                .code { background: #e9ecef; padding: 10px; border-radius: 5px; font-family: monospace; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🛡️ VulnScope</h1>
                    <p>Vérification de votre adresse email</p>
                </div>
                <div class="content">
                    <h2>Bienvenue {{ username }} !</h2>
                    <p>Merci de vous être inscrit sur VulnScope. Pour activer votre compte et commencer à utiliser la plateforme, veuillez vérifier votre adresse email.</p>
                    
                    <p style="text-align: center;">
                        <a href="{{ verification_url }}" class="button">Vérifier mon email</a>
                    </p>
                    
                    <p>Si le bouton ne fonctionne pas, copiez ce lien dans votre navigateur :</p>
                    <p class="code">{{ verification_url }}</p>
                    
                    <p>Ce lien expire dans 7 jours.</p>
                    
                    <p>Si vous n'avez pas créé de compte VulnScope, vous pouvez ignorer cet email.</p>
                </div>
                <div class="footer">
                    <p>© {{ year }} VulnScope - Plateforme de gestion des vulnérabilités</p>
                    <p>Cet email a été envoyé à {{ email }}</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        text_template = """
        Bienvenue {{ username }} !
        
        Merci de vous être inscrit sur VulnScope. Pour activer votre compte, veuillez vérifier votre adresse email en cliquant sur le lien suivant :
        
        {{ verification_url }}
        
        Ce lien expire dans 7 jours.
        
        Si vous n'avez pas créé de compte VulnScope, vous pouvez ignorer cet email.
        
        © {{ year }} VulnScope
        """
        
        from datetime import datetime
        
        context = {
            'username': username,
            'verification_url': verification_url,
            'email': email,
            'year': datetime.now().year
        }
        
        html_body = Template(html_template).render(**context)
        text_body = Template(text_template).render(**context)
        
        subject = "VulnScope - Vérifiez votre adresse email"
        
        return self._send_email(email, subject, html_body, text_body)
    
    def send_password_reset_email(self, email: str, token: str, username: str) -> bool:
        """Send password reset link"""
        reset_url = f"{self.email_config.frontend_url}/reset-password?token={token}"
        
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                .header { background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
                .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
                .button { display: inline-block; background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; margin: 20px 0; }
                .footer { text-align: center; color: #666; font-size: 12px; margin-top: 20px; }
                .code { background: #e9ecef; padding: 10px; border-radius: 5px; font-family: monospace; }
                .warning { background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔐 VulnScope</h1>
                    <p>Réinitialisation de votre mot de passe</p>
                </div>
                <div class="content">
                    <h2>Bonjour {{ username }},</h2>
                    <p>Nous avons reçu une demande de réinitialisation de votre mot de passe VulnScope.</p>
                    
                    <p style="text-align: center;">
                        <a href="{{ reset_url }}" class="button">Réinitialiser mon mot de passe</a>
                    </p>
                    
                    <p>Si le bouton ne fonctionne pas, copiez ce lien dans votre navigateur :</p>
                    <p class="code">{{ reset_url }}</p>
                    
                    <div class="warning">
                        <strong>⚠️ Sécurité :</strong> Ce lien expire dans 1 heure. Si vous n'avez pas demandé cette réinitialisation, vous pouvez ignorer cet email en toute sécurité.
                    </div>
                </div>
                <div class="footer">
                    <p>© {{ year }} VulnScope - Plateforme de gestion des vulnérabilités</p>
                    <p>Cet email a été envoyé à {{ email }}</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        text_template = """
        Bonjour {{ username }},
        
        Nous avons reçu une demande de réinitialisation de votre mot de passe VulnScope.
        
        Cliquez sur le lien suivant pour réinitialiser votre mot de passe :
        {{ reset_url }}
        
        Ce lien expire dans 1 heure.
        
        Si vous n'avez pas demandé cette réinitialisation, vous pouvez ignorer cet email.
        
        © {{ year }} VulnScope
        """
        
        from datetime import datetime
        
        context = {
            'username': username,
            'reset_url': reset_url,
            'email': email,
            'year': datetime.now().year
        }
        
        html_body = Template(html_template).render(**context)
        text_body = Template(text_template).render(**context)
        
        subject = "VulnScope - Réinitialisation de votre mot de passe"
        
        return self._send_email(email, subject, html_body, text_body)
    
    def send_password_changed_confirmation(self, email: str, username: str) -> bool:
        """Send confirmation that password was changed"""
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                .header { background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
                .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
                .footer { text-align: center; color: #666; font-size: 12px; margin-top: 20px; }
                .warning { background: #f8d7da; border-left: 4px solid #dc3545; padding: 15px; margin: 20px 0; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>✅ VulnScope</h1>
                    <p>Mot de passe modifié avec succès</p>
                </div>
                <div class="content">
                    <h2>Bonjour {{ username }},</h2>
                    <p>Votre mot de passe VulnScope a été modifié avec succès.</p>
                    
                    <div class="warning">
                        <strong>⚠️ Vous n'avez pas fait cette modification ?</strong><br>
                        Si vous n'avez pas changé votre mot de passe, contactez immédiatement notre support et sécurisez votre compte.
                    </div>
                    
                    <p>Pour votre sécurité, nous vous recommandons d'utiliser un mot de passe unique et fort.</p>
                </div>
                <div class="footer">
                    <p>© {{ year }} VulnScope - Plateforme de gestion des vulnérabilités</p>
                    <p>Cet email a été envoyé à {{ email }}</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        text_template = """
        Bonjour {{ username }},
        
        Votre mot de passe VulnScope a été modifié avec succès.
        
        Si vous n'avez pas fait cette modification, contactez immédiatement notre support.
        
        © {{ year }} VulnScope
        """
        
        from datetime import datetime
        
        context = {
            'username': username,
            'email': email,
            'year': datetime.now().year
        }
        
        html_body = Template(html_template).render(**context)
        text_body = Template(text_template).render(**context)
        
        subject = "VulnScope - Votre mot de passe a été modifié"
        
        return self._send_email(email, subject, html_body, text_body)
    
    def send_welcome_email(self, email: str, username: str) -> bool:
        """Send welcome email after verification"""
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
                .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
                .button { display: inline-block; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; margin: 20px 0; }
                .footer { text-align: center; color: #666; font-size: 12px; margin-top: 20px; }
                .features { background: white; padding: 20px; border-radius: 5px; margin: 20px 0; }
                .feature { padding: 10px 0; border-bottom: 1px solid #eee; }
                .feature:last-child { border-bottom: none; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🎉 Bienvenue sur VulnScope !</h1>
                    <p>Votre compte est maintenant activé</p>
                </div>
                <div class="content">
                    <h2>Félicitations {{ username }} !</h2>
                    <p>Votre compte VulnScope est maintenant activé. Vous pouvez commencer à utiliser la plateforme pour gérer vos scans de vulnérabilités.</p>
                    
                    <p style="text-align: center;">
                        <a href="{{ dashboard_url }}" class="button">Accéder au tableau de bord</a>
                    </p>
                    
                    <div class="features">
                        <h3>Ce que vous pouvez faire :</h3>
                        <div class="feature">🔍 <strong>Scanner</strong> - Lancez des scans de sécurité sur vos applications</div>
                        <div class="feature">📊 <strong>Rapports</strong> - Générez des rapports détaillés de vos findings</div>
                        <div class="feature">🔧 <strong>Intégrations</strong> - Connectez vos outils CI/CD et SIEM</div>
                        <div class="feature">📋 <strong>Compliance</strong> - Suivez votre conformité en temps réel</div>
                    </div>
                    
                    <p>Si vous avez des questions, n'hésitez pas à consulter notre documentation ou à contacter notre support.</p>
                </div>
                <div class="footer">
                    <p>© {{ year }} VulnScope - Plateforme de gestion des vulnérabilités</p>
                    <p>Cet email a été envoyé à {{ email }}</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        text_template = """
        Bienvenue sur VulnScope, {{ username }} !
        
        Votre compte est maintenant activé. Vous pouvez commencer à utiliser la plateforme.
        
        Accédez à votre tableau de bord : {{ dashboard_url }}
        
        Ce que vous pouvez faire :
        - Scanner vos applications pour détecter les vulnérabilités
        - Générer des rapports détaillés
        - Intégrer vos outils CI/CD et SIEM
        - Suivre votre conformité
        
        © {{ year }} VulnScope
        """
        
        from datetime import datetime
        
        context = {
            'username': username,
            'email': email,
            'dashboard_url': self.email_config.frontend_url,
            'year': datetime.now().year
        }
        
        html_body = Template(html_template).render(**context)
        text_body = Template(text_template).render(**context)
        
        subject = "Bienvenue sur VulnScope !"
        
        return self._send_email(email, subject, html_body, text_body)


# Global email service instance
_email_service: Optional[EmailService] = None


def get_email_service() -> EmailService:
    """Get or create email service singleton"""
    global _email_service
    if _email_service is None:
        _email_service = EmailService()
    return _email_service