# core/signals.py
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth.models import User
from .models import UserProfile, AgentProfile

@receiver(post_save, sender=User)
def create_user_and_agent_profiles(sender, instance, created, **kwargs):
    """
    Automatically create UserProfile for every new user.
    If user is flagged as agent, create AgentProfile too.
    """
    if created:
        # Create UserProfile
        UserProfile.objects.create(user=instance)

        # Optionally create AgentProfile if user is an agent
        if getattr(instance, 'is_agent', False):
            AgentProfile.objects.create(
                user=instance,
                commission_earned=0,
                total_sales=0,
                total_sales_volume=0,
                is_active=True  # can default to active if desired
            )

@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    """
    Ensure UserProfile always saved when User is saved.
    """
    profile, _ = UserProfile.objects.get_or_create(user=instance)
    profile.save()
