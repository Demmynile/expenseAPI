from django.conf import settings
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

class Util:
    @staticmethod
    def send_email(data):
        email= Mail(
            from_email=settings.DEFAULT_FROM_EMAIL,
            subject=data['email_subject'] , html_content = data['email_body'] , to_emails=[data['to_email']])
        try:
            sg = SendGridAPIClient(settings.SENDGRID_API_KEY)
            response = sg.send(email)
            return response.status_code
        except Exception as e:
            return str(e)
        

        