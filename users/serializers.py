from rest_framework import serializers


class SignUpSerializer(serializers.ModelSerializer):
    id = serializers.UUIDField(read_only=True)