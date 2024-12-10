from django.urls import path

from users.views import CreateUserView, ChangeUserInformationView, ChangeUserPhotoView


urlpatterns = [
    path('signup/', CreateUserView.as_view()),
    path('change-user/', ChangeUserInformationView.as_view()),
    path('change-user-photo/', ChangeUserPhotoView.as_view()),
]