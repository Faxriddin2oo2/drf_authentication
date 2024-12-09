from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers
from wx.lib.docview import DOC_NEW

from .models import User, VIA_PHONE, CODE_VERIFIED, DONE
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


class ChangeUserInformation(serializers.Serializer):
    first_name = serializers.CharField(write_only=True, required=True)
    last_name = serializers.CharField(write_only=True, required=True)
    username = serializers.CharField(write_only=True, required=True)
    password = serializers.CharField(write_only=True, required=True)
    confirm_password = serializers.CharField(write_only=True, required=True)

    def validate(self, data):
        password = data.get('password', None)
        confirm_password = data.get('confirm_password', None)
        if password != confirm_password:
            raise ValidationError(
                {
                    "message" : "Parolingiz va tasdiqlash parolingiz bir-biriga teng emas"
                }
            )
        if password:
            validate_password(password)
            validate_password(confirm_password)

        return data

    def validate_username(self,username):
        if len(username) < 5 or len(username) > 30:
            raise ValidationError(
                {
                    "message" : "Username must be between 5 and 30 characters long"
                }
            )
        if username.isdigit():
            raise ValidationError(
                {"message": "This username is entirely numeric"}
            )

        return username

    def validate_first_name(self, first_name):
        if len(first_name) < 5 or len(first_name) > 30:
            raise ValidationError(
                {
                    "message": "First name must be between 5 and 30 characters long"
                }
            )
        if first_name.isdigit():
            raise ValidationError(
                {"message": "This first name is entirely numeric"}
            )

        return first_name

    def validate_last_name(self, last_name):
        if len(last_name) < 5 or len(last_name) > 30:
            raise ValidationError(
                {
                    "message": "Last name must be between 5 and 30 characters long"
                }
            )
        if last_name.isdigit():
            raise ValidationError(
                {"message": "This last name is entirely numeric"}
            )

        return last_name

    def update(self, instance, validated_data):

        instance.first_name = validated_data.get('first_name', instance.first_name)
        instance.last_name = validated_data.get('last_name', instance.last_name)
        instance.password = validated_data.get('password', instance.password)
        instance.username = validated_data.get('username', instance.username)
        if validated_data.get('password'):
            instance.set_password(validated_data.get('password'))
        if instance.auth_status == CODE_VERIFIED:
            instance.auth_status = DONE
        instance.save()
        return instance

