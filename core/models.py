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
# BUNDLE MODEL
# ---------------------------
class Bundle(models.Model):
    """
    Bundles are managed by admin in the app. Optionally a bundle can be delivered
    via external data API (send_via_api=True). 'stock' is optional and can be used
    if you want admin-limited stock.
    """
    NETWORK_CHOICES = (
        ("MTN", "MTN"),
        ("AirtelTigo", "AirtelTigo"),
        ("Vodafone", "Vodafone"),
    )

    name = models.CharField(max_length=100)
    code = models.CharField(max_length=50, blank=True)     # vendor code if needed
    network = models.CharField(max_length=50, choices=NETWORK_CHOICES)
    price = models.DecimalField(max_digits=12, decimal_places=2)
    stock = models.IntegerField(default=0, help_text="Admin-managed stock (optional).")
    is_active = models.BooleanField(default=True)

    # If True, the app will call the external data API to deliver this bundle
    # using admin/data-source credentials. If False, the bundle is delivered locally.
    send_via_api = models.BooleanField(
        default=False,
        help_text="If checked, this bundle is delivered via configured external API."
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    admin_notes = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"{self.name} - {self.network}"


# ---------------------------
# ORDER / PURCHASE MODEL
# ---------------------------
class Purchase(models.Model):
    """
    Order history for every attempted/finished sale.
    - bundle: optional FK if admin bundle was used
    - bundle_name/network: stored for API bundles or when names change
    - source: where the bundle was sourced from (ADMIN or API)
    - transaction_reference: for payment/transmission reference (Paystack ref or API ref)
    - response_data: JSONField to keep external API response for debugging/audit
    """
    SOURCE_CHOICES = (
        ("ADMIN", "Admin bundle"),
        ("API", "External API"),
    )

    STATUS_CHOICES = (
        ("PENDING", "Pending"),
        ("PAID", "Paid"),
        ("FAILED", "Failed"),
        ("REFUNDED", "Refunded"),
    )

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    bundle = models.ForeignKey('Bundle', on_delete=models.SET_NULL, null=True, blank=True)
    bundle_name = models.CharField(max_length=200, blank=True, null=True)
    network = models.CharField(max_length=50, blank=True, null=True)
    quantity = models.PositiveIntegerField(default=1)
    amount = models.DecimalField(max_digits=14, decimal_places=2)
    recipient = models.CharField(max_length=100)  # e.g. recipient phone or username
    source = models.CharField(max_length=10, choices=SOURCE_CHOICES, default="ADMIN")
    transaction_reference = models.CharField(max_length=200, blank=True, null=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default="PENDING")
    response_data = models.JSONField(blank=True, null=True)  # external API responses, debug info
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("-created_at",)
        indexes = [
            models.Index(fields=["user"]),
            models.Index(fields=["transaction_reference"]),
        ]

    def __str__(self):
        return f"{self.user.username} - {self.bundle_name or 'Bundle'} x{self.quantity} ({self.status})"


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