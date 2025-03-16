import logging
from pathlib import Path
from typing import Any, Dict, List, Optional
from datetime import datetime

import boto3
from botocore.exceptions import ClientError
from pydantic import EmailStr

from app.core.config import settings


def send_email(
    email_to: str,
    subject: str,
    html_content: str,
) -> bool:
    """
    Send an email using Amazon SES.
    
    Returns True if the email was sent successfully, False otherwise.
    """
    if not settings.EMAILS_ENABLED:
        logging.warning("Emails are not enabled. Would have sent email to: %s", email_to)
        return False
    
    try:
        # Create a new SES resource
        ses_client = boto3.client(
            'ses',
            region_name=settings.AWS_REGION,
            aws_access_key_id=settings.AWS_ACCESS_KEY,
            aws_secret_access_key=settings.AWS_SECRET_KEY,
        )
        
        # Create the email message
        response = ses_client.send_email(
            Source=f"{settings.EMAILS_FROM_NAME} <{settings.EMAILS_FROM_EMAIL}>",
            Destination={
                'ToAddresses': [email_to],
            },
            Message={
                'Subject': {
                    'Data': subject,
                    'Charset': 'UTF-8'
                },
                'Body': {
                    'Html': {
                        'Data': html_content,
                        'Charset': 'UTF-8'
                    }
                }
            }
        )
        logging.info("Email sent! Message ID: %s", response['MessageId'])
        return True
    except ClientError as e:
        logging.error("Failed to send email: %s", str(e))
        return False


def send_verification_email(email_to: str, token: str) -> bool:
    """
    Send an email verification link to a user.
    """
    subject = f"{settings.PROJECT_NAME} - Verify Your Email"
    
    # In a real application, this would be your frontend URL
    verification_link = f"{settings.OAUTH_REDIRECT_URL.rsplit('/', 1)[0]}/verify-email?token={token}"
    
    html_content = f"""
    <html>
        <head>
            <title>{subject}</title>
        </head>
        <body>
            <h1>Verify Your Email Address</h1>
            <p>Thank you for registering with {settings.PROJECT_NAME}!</p>
            <p>Please click the link below to verify your email address:</p>
            <p><a href="{verification_link}">{verification_link}</a></p>
            <p>This link will expire in 24 hours.</p>
            <p>If you did not register for an account, you can safely ignore this email.</p>
        </body>
    </html>
    """
    
    return send_email(email_to, subject, html_content)


def send_password_reset_email(email_to: str, token: str, username: str) -> None:
    """
    Send a password reset email with a reset link.
    
    Args:
        email_to: The recipient's email address.
        token: The password reset token.
        username: The user's name for personalization.
    """
    # In a production environment, replace with actual email sending logic using Amazon SES
    password_reset_link = f"{settings.FRONTEND_URL}/reset-password?token={token}"
    
    subject = f"{settings.PROJECT_NAME} - Password Reset"
    
    html_content = f"""
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
            .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
            .header {{ background-color: #4a76a8; color: white; padding: 10px 20px; }}
            .content {{ padding: 20px; background-color: #f9f9f9; }}
            .footer {{ text-align: center; margin-top: 20px; font-size: 12px; color: #777; }}
            .btn {{ display: inline-block; padding: 10px 20px; background-color: #4a76a8; color: white; 
                  text-decoration: none; border-radius: 4px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h2>{settings.PROJECT_NAME}</h2>
            </div>
            <div class="content">
                <p>Hi {username},</p>
                <p>You've requested to reset your password. Click the button below to create a new password:</p>
                <p style="text-align: center; margin: 30px 0;">
                    <a href="{password_reset_link}" class="btn">Reset Your Password</a>
                </p>
                <p>This link will expire in 24 hours.</p>
                <p>If you didn't request a password reset, please ignore this email or contact support if you have concerns.</p>
                <p>Thanks,<br>The {settings.PROJECT_NAME} Team</p>
            </div>
            <div class="footer">
                <p>This is an automated message, please do not reply to this email.</p>
                <p>© {datetime.now().year} {settings.PROJECT_NAME}. All rights reserved.</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    # For development, just print the email content
    if settings.ENVIRONMENT == "development":
        print(f"\n--- Password Reset Email ---")
        print(f"To: {email_to}")
        print(f"Subject: {subject}")
        print(f"Reset Link: {password_reset_link}")
        print(f"Content: {html_content}")
        print(f"---------------------------\n")
        return
    
    # In production, use Amazon SES
    try:
        # Configure the SES client
        ses_client = boto3.client(
            'ses',
            region_name=settings.AWS_REGION,
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
        )
        
        # Send the email
        response = ses_client.send_email(
            Source=settings.EMAIL_FROM,
            Destination={"ToAddresses": [email_to]},
            Message={
                "Subject": {"Data": subject},
                "Body": {"Html": {"Data": html_content}},
            },
        )
        
        logging.info(f"Password reset email sent to {email_to}. Message ID: {response['MessageId']}")
    except Exception as e:
        logging.error(f"Failed to send password reset email to {email_to}. Error: {e}")
        raise


def send_mfa_code_email(email_to: str, code: str, username: str) -> None:
    """
    Send an MFA verification code email.
    
    Args:
        email_to: The recipient's email address.
        code: The MFA verification code.
        username: The user's name for personalization.
    """
    subject = f"{settings.PROJECT_NAME} - Your MFA Verification Code"
    
    html_content = f"""
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
            .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
            .header {{ background-color: #4a76a8; color: white; padding: 10px 20px; }}
            .content {{ padding: 20px; background-color: #f9f9f9; }}
            .code {{ font-family: monospace; font-size: 24px; font-weight: bold; 
                    letter-spacing: 5px; background-color: #eee; padding: 10px 20px; 
                    border-radius: 4px; margin: 20px 0; display: inline-block; }}
            .footer {{ text-align: center; margin-top: 20px; font-size: 12px; color: #777; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h2>{settings.PROJECT_NAME}</h2>
            </div>
            <div class="content">
                <p>Hi {username},</p>
                <p>You've requested to enable Multi-Factor Authentication (MFA) for your account.</p>
                <p>Your verification code is:</p>
                <div style="text-align: center;">
                    <div class="code">{code}</div>
                </div>
                <p>This code will expire in 10 minutes.</p>
                <p>If you didn't request to enable MFA, please secure your account by changing your password immediately.</p>
                <p>Thanks,<br>The {settings.PROJECT_NAME} Team</p>
            </div>
            <div class="footer">
                <p>This is an automated message, please do not reply to this email.</p>
                <p>© {datetime.now().year} {settings.PROJECT_NAME}. All rights reserved.</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    # For development, just print the email content
    if settings.ENVIRONMENT == "development":
        print(f"\n--- MFA Code Email ---")
        print(f"To: {email_to}")
        print(f"Subject: {subject}")
        print(f"MFA Code: {code}")
        print(f"---------------------------\n")
        return
    
    # In production, use Amazon SES
    try:
        # Configure the SES client
        ses_client = boto3.client(
            'ses',
            region_name=settings.AWS_REGION,
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
        )
        
        # Send the email
        response = ses_client.send_email(
            Source=settings.EMAIL_FROM,
            Destination={"ToAddresses": [email_to]},
            Message={
                "Subject": {"Data": subject},
                "Body": {"Html": {"Data": html_content}},
            },
        )
        
        logging.info(f"MFA code email sent to {email_to}. Message ID: {response['MessageId']}")
    except Exception as e:
        logging.error(f"Failed to send MFA code email to {email_to}. Error: {e}")
        raise


def send_security_notification_email(email_to: str, event_type: str, details: dict, username: str) -> None:
    """
    Send a security notification email for important security events.
    
    Args:
        email_to: The recipient's email address.
        event_type: The type of security event (e.g., 'login_attempt', 'password_change').
        details: Dictionary with event details.
        username: The user's name for personalization.
    """
    # Map event types to human-readable titles and descriptions
    event_templates = {
        "login_attempt": {
            "title": "Unusual Login Attempt Detected",
            "description": "We detected an unusual login attempt to your account.",
            "action": "If this was not you, please change your password immediately and enable MFA if not already enabled.",
        },
        "password_change": {
            "title": "Your Password Was Changed",
            "description": "Your account password was recently changed.",
            "action": "If you did not make this change, please contact support immediately.",
        },
        "mfa_enabled": {
            "title": "Multi-Factor Authentication Enabled",
            "description": "Multi-Factor Authentication has been enabled for your account.",
            "action": "This adds an extra layer of security to your account. If you did not make this change, please contact support immediately.",
        },
        "mfa_disabled": {
            "title": "Multi-Factor Authentication Disabled",
            "description": "Multi-Factor Authentication has been disabled for your account.",
            "action": "Your account is now protected by password only. If you did not make this change, please contact support immediately and re-enable MFA.",
        },
        "account_locked": {
            "title": "Your Account Has Been Temporarily Locked",
            "description": "Your account has been temporarily locked due to multiple failed login attempts.",
            "action": "You can try again after the lockout period expires or use the 'Forgot Password' feature to reset your password and unlock your account.",
        },
    }
    
    # Get the template for this event type
    template = event_templates.get(event_type, {
        "title": "Security Alert",
        "description": "An important security event has occurred on your account.",
        "action": "If you did not initiate this action, please contact support immediately.",
    })
    
    subject = f"{settings.PROJECT_NAME} - {template['title']}"
    
    # Format the timestamp
    from datetime import datetime
    timestamp = details.get("timestamp", datetime.utcnow())
    if isinstance(timestamp, datetime):
        timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
    
    # Format IP address and location if present
    ip_address = details.get("ip_address", "Unknown")
    location = details.get("location", "Unknown location")
    user_agent = details.get("user_agent", "Unknown device")
    
    # Create the HTML content for event details
    event_details_html = ""
    for key, value in details.items():
        if key not in ["ip_address", "location", "user_agent", "timestamp"]:
            event_details_html += f"<tr><td>{key.replace('_', ' ').title()}</td><td>{value}</td></tr>"
    
    html_content = f"""
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
            .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
            .header {{ background-color: #4a76a8; color: white; padding: 10px 20px; }}
            .content {{ padding: 20px; background-color: #f9f9f9; }}
            .footer {{ text-align: center; margin-top: 20px; font-size: 12px; color: #777; }}
            .alert {{ background-color: #ffebee; border-left: 4px solid #f44336; padding: 10px; margin: 10px 0; }}
            table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
            th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
            th {{ background-color: #f2f2f2; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h2>{settings.PROJECT_NAME} - Security Alert</h2>
            </div>
            <div class="content">
                <p>Hi {username},</p>
                <p>{template['description']}</p>
                
                <div class="alert">
                    <p><strong>{template['action']}</strong></p>
                </div>
                
                <h3>Event Details</h3>
                <table>
                    <tr>
                        <th>Detail</th>
                        <th>Information</th>
                    </tr>
                    <tr>
                        <td>Event</td>
                        <td>{event_type.replace('_', ' ').title()}</td>
                    </tr>
                    <tr>
                        <td>Time</td>
                        <td>{timestamp}</td>
                    </tr>
                    <tr>
                        <td>IP Address</td>
                        <td>{ip_address}</td>
                    </tr>
                    <tr>
                        <td>Location</td>
                        <td>{location}</td>
                    </tr>
                    <tr>
                        <td>Device</td>
                        <td>{user_agent}</td>
                    </tr>
                    {event_details_html}
                </table>
                
                <p>If you did not perform this action, please secure your account immediately by:</p>
                <ol>
                    <li>Changing your password</li>
                    <li>Enabling Multi-Factor Authentication (if not already enabled)</li>
                    <li>Contacting our support team</li>
                </ol>
                
                <p>Thanks,<br>The {settings.PROJECT_NAME} Security Team</p>
            </div>
            <div class="footer">
                <p>This is an automated message, please do not reply to this email.</p>
                <p>© {datetime.now().year} {settings.PROJECT_NAME}. All rights reserved.</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    # For development, just print the email content
    if settings.ENVIRONMENT == "development":
        print(f"\n--- Security Notification Email ---")
        print(f"To: {email_to}")
        print(f"Subject: {subject}")
        print(f"Event Type: {event_type}")
        print(f"Details: {details}")
        print(f"---------------------------\n")
        return
    
    # In production, use Amazon SES
    try:
        # Configure the SES client
        ses_client = boto3.client(
            'ses',
            region_name=settings.AWS_REGION,
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
        )
        
        # Send the email
        response = ses_client.send_email(
            Source=settings.EMAIL_FROM,
            Destination={"ToAddresses": [email_to]},
            Message={
                "Subject": {"Data": subject},
                "Body": {"Html": {"Data": html_content}},
            },
        )
        
        logging.info(f"Security notification email sent to {email_to}. Message ID: {response['MessageId']}")
    except Exception as e:
        logging.error(f"Failed to send security notification email to {email_to}. Error: {e}")
        raise 