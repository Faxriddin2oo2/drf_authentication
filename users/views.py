from rest_framework import permissions
from rest_framework.generics import CreateAPIView

from users.serializers import SignUpSerializer
from .models import User


class CreateUserView(CreateAPIView):
    queryset = User.objects.all()
    permission_classes = (permissions.AllowAny,)
    serializer_class = SignUpSerializer
