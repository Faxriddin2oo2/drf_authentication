import re
import phonenumbers
from rest_framework.exceptions import ValidationError

phone_regex = re.compile(r"(\+[0-9]+\s*)?(\([0-9]+\))?[\s0-9\-]+[0-9]+")
username_regex = re.compile(r"^[a-zA-Z0-9_.-]+$")

def phone_is_valid(phone):
    phone_numer = phonenumbers.parse(phone)
    if phonenumbers.is_valid_number(phone):
        phone = 'phone'
    else:
        data = {
            "success" : False,
            "message" : "Email yoki telefon raqamingiz notog'ri"
        }
        raise ValidationError(data)

    return phone


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

