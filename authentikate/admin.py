from django.contrib import admin
from authentikate.models import Client, User, Membership

# Register your models here.

admin.site.register(User)
admin.site.register(Client)
admin.site.register(Membership)
