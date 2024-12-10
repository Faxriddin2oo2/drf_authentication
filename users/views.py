from intake.container.serializer import serializers
from rest_framework.response import Response
from rest_framework import permissions
from rest_framework.generics import CreateAPIView, UpdateAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView

from users.serializers import SignUpSerializer, ChangeUserInformation, ChangeUserPhotoSerializer
from .models import User


class CreateUserView(CreateAPIView):
    queryset = User.objects.all()
    permission_classes = (permissions.AllowAny,)
    serializer_class = SignUpSerializer


class ChangeUserInformationView(UpdateAPIView):
    permission_classes = [IsAuthenticated, ]
    serializer_class = ChangeUserInformation
    http_method_names = ['patch', 'put']

    def get_object(self):
        return self.request.user

    def update(self, request, *args, **kwargs):
        super(ChangeUserInformationView, self).update(request, *args, **kwargs)
        data = {
            'success' : True,
            'message' : "User updated successfully",
            'auth_status' : self.request.user.auth_status,
        }
        return Response(data, status=200)

    def partial_update(self, request, *args, **kwargs):
        super(ChangeUserInformationView, self).partial_update(request, *args, **kwargs)
        data = {
            'success': True,
            'message': "User updated successfully",
            'auth_status': self.request.user.auth_status
        }
        return Response(data, status=200)


class ChangeUserPhotoView(APIView):
    permission_classes = [IsAuthenticated, ]
    def put(self, request, *args, **kwargs):
        serializer = ChangeUserPhotoSerializer(data=request.data)
        if serializer.is_valid():
            user = request.user
            serializer.update(user, serializer.validated_data)
            return Response({
                'image' : "Rasm muvaffaqiyatli o'zgartirildi"
            }, status=200)
        return Response(
            serializer.errors, status=400
        )