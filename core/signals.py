# core/signals.py
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth.models import User

from .models import UserProfile, AgentProfile

@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    """
    Ensure a UserProfile always exists for every User.
    """
    if created:
        UserProfile.objects.create(user=instance)

@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    """
    Ensure profile saved (useful if future fields change).
    """
    try:
        instance.userprofile.save()
    except Exception:
        # if userprofile does not exist for some reason, create it
        UserProfile.objects.get_or_create(user=instance)

@receiver(post_save, sender=User)
def create_profiles(sender, instance, created, **kwargs):
    if created:
        # Create user profile
        profile = UserProfile.objects.create(user=instance)

        # Create agent profile linked to user (but inactive by default)
        AgentProfile.objects.create(user=instance, commission_earned=0, total_sales=0, total_sales_volume=0)