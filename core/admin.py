from django.contrib import admin
from .models import UserProfile, AgentProfile, Bundle, Purchase, AppSettings, ContactMessage, Sale

admin.site.register(UserProfile)
admin.site.register(AgentProfile)
admin.site.register(Bundle)
admin.site.register(Purchase)
admin.site.register(AppSettings)
admin.site.register(ContactMessage)
admin.site.register(Sale)
