from rest_framework import serializers
from .models import User, VIA_PHONE
from .utility import phone_is_valid

from rest_framework.exceptions import ValidationError


class SignUpSerializer(serializers.ModelSerializer):
    id = serializers.UUIDField(read_only=True)

    def __init__(self, *args, **kwargs):
        super(SignUpSerializer).__init__(*args, **kwargs)
        self.fields['phone_number'] = serializers.CharField(required=False)

    class Meta:
        model = User
        fields = (
            "id",
            "auth_type",
            "auth_status"
        )
        extra_kwargs = {
            "auth_type" : {'read_only':True, 'required':False},
            "auth_status" : {'read_only':True, 'required':False},
        }

    # def create(self, validated_data):
    #     user = super(SignUpSerializer, self).create(validated_data)
    #     code = user.create_verify_code(VIA_PHONE)
    #     send_email(user.phone_number, code)
    #     user.save()
    #     return user


    def validate(self, data):
        super(SignUpSerializer, self).validate(data)
        data = self.auth_validate(data)
        return data


    @staticmethod
    def auth_validate(data):
        user_input = str(data.get('phone_number'))
        input_type = phone_is_valid(user_input)
        if input_type == 'phone':
            data = {
                'phone_number': user_input,
                'auth_type': VIA_PHONE
            }
        else:
            data = {
                'success': False,
                'message': "You must send phone number"
            }
            raise ValidationError(data)

        return data

    def validate_phone_number(self, value):
        value = value.lower()
        if value and User.objects.filter(phone_number=value).exists():
            data = {
                "success" : False,
                'message' : "Bu telefon raqami allaqachon ma'lumotlar bazasida bor"
            }
            raise ValidationError(data)

        return value

    def to_representation(self, instance):
        data = super(SignUpSerializer, self).to_representation(instance)
        data.update(instance.token())

        return data