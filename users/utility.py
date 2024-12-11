import re
import threading

from django.core.mail import EmailMessage

import phonenumbers
from django.template.loader import render_to_string
from rest_framework.exceptions import ValidationError

phone_regex = re.compile(r"(\+[0-9]+\s*)?(\([0-9]+\))?[\s0-9\-]+[0-9]+")
username_regex = re.compile(r"^[a-zA-Z0-9_.-]+$")

# def phone_is_valid(phone):
#     # phone_numer = phonenumbers.parse(phone)
#     if phonenumbers.is_valid_number(phone):
#         phone = 'phone'
#     else:
#         data = {
#             "success" : False,
#             "message" : "Email yoki telefon raqamingiz notog'ri"
#         }
#         raise ValidationError(data)
#
#     return phone

def phone_is_valid(phone):
    try:
        # Parse the phone number string into a PhoneNumber object
        parsed_phone = phonenumbers.parse(phone, None)  # Provide the default region if needed
        if phonenumbers.is_valid_number(parsed_phone):
            return 'phone'
        else:
            raise ValidationError({
                "success": False,
                "message": "Email yoki telefon raqamingiz notog'ri"
            })
    except phonenumbers.NumberParseException:
        raise ValidationError({
            "success": False,
            "message": "Telefon raqami noto‘g‘ri formatda"
        })


def check_user_type(user_input):
    if re.fullmatch(phone_regex, user_input):
        user_input = 'phone'
    elif re.fullmatch(username_regex, user_input):
        user_input = 'username'
    else:
        data = {
            "success" : False,
            "message" : "Username yoki telefon raqamingiz noto'g'ri"
        }
        raise ValidationError(data)
    return user_input

class EmailThread(threading.Thread):

    def __init__(self, email):
        self.email = email
        threading.Thread.__init__(self)

    def run(self):
        self.email.send()

class Email:
    @staticmethod
    def send_email(data):
        email = EmailMessage(
            subject=data['subject'],
            body=data['body'],
            to=[data['to_email']]
        )
        if data.get('content_type') == 'html':
            email.content_subtype = 'html'
        EmailThread(email).start()


def send_email(email, code):
    html_content = render_to_string(
        'email/authentication/activate_account.html',
        {"code":code}
    )
    Email.send_email(
        {
            'subject':"Royhatdan o'tish",
            'to_email':email,
            'body':html_content,
            'content_type':"html"
        }
    )