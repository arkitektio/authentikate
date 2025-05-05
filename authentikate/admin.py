from django.contrib import admin
from authentikate.models import Client, User

# Register your models here.

admin.site.register(User)
admin.site.register(Client)
