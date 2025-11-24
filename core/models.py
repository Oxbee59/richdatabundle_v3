from django.db import models
from django.contrib.auth.models import User
import secrets
from django.utils import timezone
from decimal import Decimal


# ---------------------------
# USER PROFILE
# ---------------------------
class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    wallet = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    is_agent = models.BooleanField(default=False)

    # link to agent profile
    agent_profile = models.OneToOneField(
        'AgentProfile',
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )

    def __str__(self):
        return f"{self.user.username} Profile"


# ---------------------------
# AGENT PROFILE
# ---------------------------
class AgentProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)

    commission_earned = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    total_sales = models.IntegerField(default=0)
    total_sales_volume = models.DecimalField(max_digits=12, decimal_places=2, default=0.00)

    api_key = models.CharField(max_length=100, unique=True, blank=True)

    def save(self, *args, **kwargs):
        # generate API key on first save
        if not self.api_key:
            self.api_key = secrets.token_hex(24)
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Agent: {self.user.username}"


# ---------------------------
# BUNDLE MODEL
# ---------------------------
class Bundle(models.Model):
    NETWORK_CHOICES = (
        ("MTN", "MTN"),
        ("AirtelTigo", "AirtelTigo"),
        ("Vodafone", "Vodafone"),
    )

    name = models.CharField(max_length=100)
    code = models.CharField(max_length=50)
    network = models.CharField(max_length=50)
    price = models.FloatField()
    stock = models.IntegerField(default=0)

    # FIX ADDED 🔥
    is_active = models.BooleanField(default=True)

    # NEW FIELD 🔥: mark if this bundle is sold via external API
    send_via_api = models.BooleanField(
        default=False,
        help_text="If checked, this bundle will be fetched/sold via the data source API."
    )

    def __str__(self):
        return f"{self.name} - {self.network}"


# ---------------------------
# PURCHASE MODEL
# ---------------------------
class Purchase(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    bundle = models.ForeignKey('Bundle', on_delete=models.SET_NULL, null=True, blank=True)  # optional
    bundle_name = models.CharField(max_length=100, blank=True, null=True)
    network = models.CharField(max_length=50, blank=True, null=True)
    quantity = models.PositiveIntegerField(default=1)
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    recipient = models.CharField(max_length=100)  # e.g. username or phone
    status = models.CharField(max_length=20, choices=[('PAID','Paid'),('FAILED','Failed')])
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.bundle_name or 'API Bundle'} x {self.quantity}"



# ---------------------------
# APP SETTINGS MODEL
# ---------------------------
class AppSettings(models.Model):
    agent_registration_fee = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)

    # Paystack placeholders
    PAYSTACK_PUBLIC_KEY = models.CharField(max_length=200, blank=True)
    PAYSTACK_SECRET_KEY = models.CharField(max_length=200, blank=True)
    PAYSTACK_WEBHOOK_SECRET = models.CharField(max_length=200, blank=True)

    # Bundle API Key placeholder (for fetching bundles externally)
    BUNDLE_API_KEY = models.CharField(max_length=200, blank=True)

    class Meta:
        verbose_name = "Application Setting"
        verbose_name_plural = "Application Settings"

    def __str__(self):
        return "Global App Settings"
    

    
class Settings(models.Model):
    key = models.CharField(max_length=100, unique=True)
    value = models.CharField(max_length=200)

    def __str__(self):
        return f"{self.key}: {self.value}"

class Withdrawal(models.Model):
    STATUS_CHOICES = (
        ("PENDING", "Pending"),
        ("COMPLETED", "Completed"),
        ("FAILED", "Failed"),
    )
    agent = models.ForeignKey(User, on_delete=models.CASCADE)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    mobile_number = models.CharField(max_length=20)
    network = models.CharField(max_length=20)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default="PENDING")
    processed_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"{self.agent.username} - GHS {self.amount} - {self.status}"


class Sale(models.Model):
    agent = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sales')
    bundle = models.ForeignKey('Bundle', on_delete=models.CASCADE)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    quantity = models.PositiveIntegerField(default=1)
    timestamp = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        is_new = self._state.adding
        super().save(*args, **kwargs)

        if is_new:
            agent_profile = self.agent.userprofile.agent_profile
            total_sale_amount = self.price * self.quantity
            commission_rate = Decimal("0.05")
            agent_profile.commission_earned += total_sale_amount * commission_rate
            agent_profile.total_sales += self.quantity
            agent_profile.total_sales_volume += total_sale_amount
            agent_profile.save()
