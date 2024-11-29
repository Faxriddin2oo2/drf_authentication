import uuid

from django.contrib.auth.models import AbstractUser
from django.core.validators import FileExtensionValidator
from django.db import models

ORDINARY_USER, MANAGER, ADMIN = ('ordinary_user', 'manager', 'admin')
VIA_PHONE = 'via_phone'
NEW, CODE_VERIFIED, DONE, PHOTO_DONE = ('new', 'code_verified', 'done', 'photo_done')

class BaseModel(models.Model):
    id = models.UUIDField(unique=True, default=uuid.uuid4, editable=False, primary_key=True)
    created_time = models.DateTimeField(auto_now_add=True)
    updated_time = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True

class User(AbstractUser, BaseModel):
    USER_ROLES = (
        (ORDINARY_USER, ORDINARY_USER),
        (MANAGER, MANAGER),
        (ADMIN, ADMIN)
    )
    AUTH_TYPE = (
        (VIA_PHONE, VIA_PHONE)
    )
    AUTH_STATUS = (
        (NEW, NEW),
        (CODE_VERIFIED, CODE_VERIFIED),
        (DONE, DONE),
        (PHOTO_DONE, PHOTO_DONE)
    )
    user_roles = models.CharField(max_length=31, choices=USER_ROLES, default=ORDINARY_USER)
    auth_type = models.CharField(max_length=31, choices=AUTH_TYPE)
    auth_status = models.CharField(max_length=31, choices=AUTH_STATUS, default=NEW)
    email = models.EmailField(null=True, blank=True, unique=True)
    phone_number = models.CharField(max_length=13, null=True, blank=True, unique=True)
    photo = models.ImageField(upload_to='user_photos/', null=True, blank=True,
                              validators=[FileExtensionValidator(allowed_extensions=['jpg', 'jpeg', 'png', 'heic', 'heif'])])



    def __str__(self):
        return self.username

