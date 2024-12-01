from rest_framework import serializers
from .models import User, VIA_PHONE


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
