from django.db import models
from django.contrib.auth.models import User
import secrets
from django.utils import timezone
from decimal import Decimal

# ---------------------------
# USER PROFILE
# ---------------------------
class UserProfile(models.Model):
    """
    Single wallet per user. Agents are just users with `is_agent=True`.
    Keep a nullable one-to-one to agent profile for agent-specific metadata.
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    wallet = models.DecimalField(max_digits=12, decimal_places=2, default=Decimal("0.00"))
    is_agent = models.BooleanField(default=False)

    # link to agent profile (optional)
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

    # payment flag
    has_paid = models.BooleanField(default=False)

    # sales counters (optional)
    total_sales = models.IntegerField(default=0)
    total_sales_volume = models.DecimalField(max_digits=14, decimal_places=2, default=Decimal("0.00"))

    # API KEYS
    public_key = models.CharField(max_length=120, unique=True, null=False, blank=False)
    secret_key = models.CharField(max_length=120, unique=True, null=False, blank=False)

    def generate_keys(self):
        self.public_key = "PUB-" + secrets.token_hex(16)
        self.secret_key = "SEC-" + secrets.token_hex(32)
        self.save()

    def __str__(self):
        return f"AgentProfile: {self.user.username}"
# ---------------------------
# BUNDLE MODEL (FINAL VERSION)
# ---------------------------
class Bundle(models.Model):

    NETWORK_CHOICES = (
        ("MTN", "MTN"),
        ("AirtelTigo", "AirtelTigo"),
        ("Vodafone", "Vodafone"),
    )

    name = models.CharField(max_length=120)
    vendor_code = models.CharField(max_length=80, blank=True, null=True,
        help_text="Package size or vendor code used by SmartDataLink API")

    api_package_id = models.CharField(max_length=120, blank=True, null=True,
        help_text="Future support if API requires a package ID")

    network = models.CharField(max_length=50, choices=NETWORK_CHOICES)

    price = models.DecimalField(
        max_digits=12, decimal_places=2,
        help_text="Selling price on your platform"
    )

    vendor_price = models.DecimalField(
        max_digits=12, decimal_places=2, default=0,
        help_text="API cost if SmartDataLink charges different price"
    )

    stock = models.IntegerField(default=0)
    is_active = models.BooleanField(default=True)

    send_via_api = models.BooleanField(
        default=False,
        help_text="If True, delivery goes through SmartDataLink API"
    )

    # Optional tags
    admin_notes = models.TextField(blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.network} - {self.name}"


# ---------------------------
# PURCHASE MODEL (FINAL VERSION)
# ---------------------------
class Purchase(models.Model):

    SOURCE_CHOICES = (
        ("ADMIN", "Admin Bundle"),
        ("API", "SmartDataLink API"),
    )

    STATUS_CHOICES = (
        ("PENDING", "Pending"),
        ("PAID", "Paid"),
        ("FAILED", "Failed"),
        ("REFUNDED", "Refunded"),
    )

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    bundle = models.ForeignKey('Bundle', on_delete=models.SET_NULL,
                               null=True, blank=True)

    bundle_name = models.CharField(max_length=200, blank=True, null=True)
    network = models.CharField(max_length=50, blank=True, null=True)

    quantity = models.PositiveIntegerField(default=1)
    amount = models.DecimalField(max_digits=14, decimal_places=2)

    recipient = models.CharField(max_length=100)

    source = models.CharField(
        max_length=10, choices=SOURCE_CHOICES, default="ADMIN"
    )

    # Saving API reference
    transaction_reference = models.CharField(
        max_length=200, blank=True, null=True,
        help_text="API order reference or paystack reference"
    )

    # API JSON response saved for debugging
    response_data = models.JSONField(
        blank=True, null=True,
        help_text="Raw SmartDataLink API response for audit"
    )

    status = models.CharField(
        max_length=10,
        choices=STATUS_CHOICES,
        default="PENDING"
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("-created_at",)
        indexes = [
            models.Index(fields=["user"]),
            models.Index(fields=["transaction_reference"]),
        ]

    def __str__(self):
        return f"{self.bundle_name or 'Bundle'} - {self.status}"


# ---------------------------
# APP SETTINGS MODEL
# ---------------------------
class AppSettings(models.Model):
    """
    Global admin settings. You can keep configuring keys here or prefer environment variables.
    """

    agent_registration_fee = models.DecimalField(max_digits=12, decimal_places=2, default=Decimal("0.00"))

    # Paystack placeholders
    PAYSTACK_PUBLIC_KEY = models.CharField(max_length=200, blank=True)
    PAYSTACK_SECRET_KEY = models.CharField(max_length=200, blank=True)
    PAYSTACK_WEBHOOK_SECRET = models.CharField(max_length=200, blank=True)

    # Data API
    SMART_API_KEY = models.CharField(max_length=200, blank=True)
    SMART_BASE_URL = models.CharField(max_length=300, blank=True)
    SMART_API_SECRET = models.CharField(max_length=200, blank=True)


    # NEW FIELDS FOR HISTORY
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Application Setting"
        verbose_name_plural = "Application Settings"

    def __str__(self):
        return "Global App Settings"


# ---------------------------
# SIMPLE KEY-VALUE SETTINGS (optional)
# ---------------------------
class Settings(models.Model):
    key = models.CharField(max_length=100, unique=True)
    value = models.CharField(max_length=500)

    def __str__(self):
        return f"{self.key}: {self.value}"
# Add to core/models.py

class ContactMessage(models.Model):
    user = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL)
    email = models.EmailField(null=True, blank=True)
    subject = models.CharField(max_length=255)
    message = models.TextField()
    created_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"{self.user.username if self.user else self.email} - {self.subject}"

class Sale(models.Model):
    agent = models.ForeignKey(User, on_delete=models.CASCADE)
    bundle = models.ForeignKey(Bundle, on_delete=models.CASCADE)
    price = models.DecimalField(max_digits=14, decimal_places=2)
    quantity = models.PositiveIntegerField(default=1)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.agent.username} sold {self.bundle.name} x{self.quantity}"

class WalletTransaction(models.Model):
    TRANSACTION_TYPE = (
        ("FUND", "Fund Wallet"),
        ("DEDUCT", "Deduct Wallet"),
    )

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="wallet_transactions")
    transaction_type = models.CharField(max_length=10, choices=TRANSACTION_TYPE)
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    reason = models.CharField(max_length=255, blank=True, null=True)
    performed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name="performed_wallet_transactions")
    created_at = models.DateTimeField(auto_now_add=True)
    paystack_reference = models.CharField(max_length=200, blank=True, null=True)
    success = models.BooleanField(default=True)  # True if transaction succeeded (Paystack or local)

    class Meta:
        ordering = ("-created_at",)

    def __str__(self):
        return f"{self.user.username} | {self.transaction_type} | {self.amount} | {self.created_at.strftime('%Y-%m-%d %H:%M')}"