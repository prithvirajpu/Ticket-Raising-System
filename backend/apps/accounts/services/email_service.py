import resend
from django.conf import settings

resend.api_key = settings.RESEND_API_KEY


class EmailService:

    @staticmethod
    def send_welcome_email(user):
        try:
            # You can replace this placeholder with your actual frontend app URL
            dashboard_url = getattr(settings, 'FRONTEND_URL', 'https://your-trs-app.com/dashboard')

            resend.Emails.send({
                "from": settings.EMAIL_FROM,
                "to": [user.email],
                "subject": "Welcome to TRS! 🚀",
                "html": f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="utf-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Welcome to TRS</title>
                </head>
                <body style="margin: 0; padding: 0; background-color: #f4f6f8; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; -webkit-font-smoothing: antialiased;">
                    <table width="100%" border="0" cellspacing="0" cellpadding="0" style="background-color: #f4f6f8; padding: 40px 20px;">
                        <tr>
                            <td align="center">
                                <table width="100%" max-width="600" style="max-width: 600px; background-color: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.05); border: 1px solid #e1e8ed;" border="0" cellspacing="0" cellpadding="0">
                                    
                                    <tr>
                                        <td style="background-color: #1e293b; padding: 32px 40px; text-align: center;">
                                            <h1 style="margin: 0; color: #ffffff; font-size: 28px; font-weight: 800; letter-spacing: -0.5px;">
                                                TRS <span style="color: #3b82f6;">🚀</span>
                                            </h1>
                                            <p style="margin: 4px 0 0 0; color: #94a3b8; font-size: 14px; text-transform: uppercase; letter-spacing: 1.5px;">Ticket Resolution System</p>
                                        </td>
                                    </tr>

                                    <tr>
                                        <td style="padding: 40px 40px 20px 40px;">
                                            <h2 style="margin: 0 0 16px 0; color: #0f172a; font-size: 24px; font-weight: 700; line-height: 1.3;">
                                                Hey {user.name}, welcome aboard!
                                            </h2>
                                            <p style="margin: 0 0 24px 0; color: #475569; font-size: 16px; line-height: 1.6;">
                                                We're thrilled to have you here. Setting up your account was the first step—now let's get you ready to manage, track, and resolve your issues like a pro.
                                            </p>
                                        </td>
                                    </tr>

                                    <tr>
                                        <td style="padding: 0 40px 30px 40px;">
                                            <div style="background-color: #f8fafc; border-radius: 8px; padding: 24px; border: 1px solid #f1f5f9;">
                                                <h3 style="margin: 0 0 16px 0; color: #1e293b; font-size: 15px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px;">What you can do next:</h3>
                                                
                                                <div style="margin-bottom: 16px; display: flex; align-items: flex-start;">
                                                    <span style="font-size: 18px; margin-right: 12px; line-height: 1;">⚡</span>
                                                    <div>
                                                        <strong style="color: #0f172a; font-size: 15px; display: block;">Instant Ticket Creation</strong>
                                                        <span style="color: #64748b; font-size: 14px;">Raise support requests in seconds with custom priorities.</span>
                                                    </div>
                                                </div>

                                                <div style="margin-bottom: 16px; display: flex; align-items: flex-start;">
                                                    <span style="font-size: 18px; margin-right: 12px; line-height: 1;">⏱️</span>
                                                    <div>
                                                        <strong style="color: #0f172a; font-size: 15px; display: block;">Real-time Tracking</strong>
                                                        <span style="color: #64748b; font-size: 14px;">Get live status updates as our team resolves your tickets.</span>
                                                    </div>
                                                </div>

                                                <div style="display: flex; align-items: flex-start;">
                                                    <span style="font-size: 18px; margin-right: 12px; line-height: 1;">💬</span>
                                                    <div>
                                                        <strong style="color: #0f172a; font-size: 15px; display: block;">Collaborative Support</strong>
                                                        <span style="color: #64748b; font-size: 14px;">Communicate directly with operators right inside the app.</span>
                                                    </div>
                                                </div>
                                            </div>
                                        </td>
                                    </tr>

                                    <tr>
                                        <td style="padding: 0 40px;">
                                            <hr style="border: 0; border-top: 1px solid #f1f5f9; margin: 0;">
                                        </td>
                                    </tr>

                                    <tr>
                                        <td style="padding: 30px 40px 40px 40px;">
                                            <p style="margin: 0; color: #475569; font-size: 15px; line-height: 1.6;">
                                                Best regards,<br>
                                                <strong style="color: #0f172a;">The TRS Team</strong>
                                            </p>
                                        </td>
                                    </tr>

                                </table>

                                <table width="100%" max-width="600" style="max-width: 600px; text-align: center; margin-top: 24px;" border="0" cellspacing="0" cellpadding="0">
                                    <tr>
                                        <td>
                                            <p style="margin: 0 0 8px 0; color: #94a3b8; font-size: 12px;">
                                                You received this email because you registered on the Ticket Raising System.
                                            </p>
                                            <p style="margin: 0; color: #94a3b8; font-size: 12px;">
                                                © 2026 TRS Inc. All rights reserved.
                                            </p>
                                        </td>
                                    </tr>
                                </table>

                            </td>
                        </tr>
                    </table>
                </body>
                </html>
                """
            })

            return True

        except Exception as e:
            print("WELCOME EMAIL ERROR:", str(e))
            return False