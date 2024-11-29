from django.contrib import admin

from .models import User

class UserModelAdmin(admin.ModelAdmin):
    list_display = ['id', 'email', 'phone_number']


admin.site.register(User, UserModelAdmin)
