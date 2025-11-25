# core/views.py
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login as auth_login, logout
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from django.conf import settings
from django.urls import reverse
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone

import requests
import json
from decimal import Decimal

from .models import (
    UserProfile, AgentProfile, Bundle, Purchase, AppSettings,
    Sale, ContactMessage
)
from django.contrib.auth.models import User


# -------------------
# AUTH: signup / login / logout
# -------------------
def signup_user(request):
    if request.method == "POST":
        username = request.POST.get("username")
        email = request.POST.get("email")
        password = request.POST.get("password")
        confirm = request.POST.get("confirm_password")

        if password != confirm:
            messages.error(request, "Passwords do not match.")
            return redirect("signup")

        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already taken.")
            return redirect("signup")

        user = User.objects.create_user(username=username, email=email, password=password)
        UserProfile.objects.get_or_create(user=user)
        messages.success(request, "Account created successfully. Please login.")
        return redirect("login")

    return render(request, "signup.html")


def login_user(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        user = authenticate(request, username=username, password=password)
        if user:
            auth_login(request, user)
            return redirect("agent_dashboard")
        messages.error(request, "Invalid credentials.")
    return render(request, "login.html")


def logout_user(request):
    logout(request)
    return redirect("login")


# -------------------
# AGENT DASHBOARD (no commissions)
# -------------------
@login_required
def agent_dashboard(request):
    user = request.user
    profile, _ = UserProfile.objects.get_or_create(user=user)
    # agent_profile may be None for normal users
    agent_profile = None
    try:
        agent_profile = AgentProfile.objects.get(user=user)
    except AgentProfile.DoesNotExist:
        agent_profile = None

    wallet_balance = profile.wallet
    # metrics (no commissions)
    total_orders = Purchase.objects.filter(user=user).count()
    total_spent = Purchase.objects.filter(user=user, status="PAID").aggregate(
        total_amount=models.Sum('amount')
    )['total_amount'] or Decimal("0.00")

    recent_orders = Purchase.objects.filter(user=user).order_by("-created_at")[:10]

    context = {
        "wallet_balance": wallet_balance,
        "total_orders": total_orders,
        "total_spent": total_spent,
        "recent_orders": recent_orders,
        "user_name": user.username,
    }
    return render(request, "agent_dashboard.html", context)


# -------------------
# Profile & Purchase History (Order History)
# -------------------
@login_required
def profile(request):
    profile, _ = UserProfile.objects.get_or_create(user=request.user)
    return render(request, "profile.html", {"profile": profile})


@login_required
def purchases(request):
    user_purchases = Purchase.objects.filter(user=request.user).order_by("-created_at")
    return render(request, "purchases.html", {"purchases": user_purchases})


# -------------------
# API Docs (for agents who want to integrate)
# -------------------
@login_required
def api_docs(request):
    if not request.user.userprofile.is_agent:
        return render(request, "not_authorized.html", {"message": "You must be an agent to access the API."})

    # pulled from your Smartdatalink documentation
    context = {
        "api_key": request.user.userprofile.agent_profile.api_key if hasattr(request.user, 'userprofile') and request.user.userprofile.agent_profile else None,
        "base_url": settings.SMART_BASE_URL if hasattr(settings, "SMART_BASE_URL") else "https://blessdatahub.com/api/",
        "endpoints": [
            {"name": "Create Order", "url": "/api/create_order.php", "method": "POST", "description": "Create a single order"},
            {"name": "Bulk Orders", "url": "/api/create_order.php", "method": "POST", "description": "Send multiple orders in one request"},
            {"name": "Check Order Status", "url": "/api/check_order_status.php", "method": "GET", "description": "Check order status by order_id"},
        ]
    }
    return render(request, "api_docs.html", context)


# -------------------
# Become agent (pay registration fee from wallet)
# -------------------
@login_required
def become_agent(request):
    user_profile = request.user.userprofile
    registration_fee = 0.0
    s = AppSettings.objects.first()
    if s:
        registration_fee = float(s.agent_registration_fee)
    if user_profile.is_agent:
        messages.info(request, "You are already an agent.")
        return redirect("agent_dashboard")

    if request.method == "POST":
        if user_profile.wallet >= Decimal(str(registration_fee)):
            user_profile.wallet -= Decimal(str(registration_fee))
            user_profile.is_agent = True
            agent_profile = AgentProfile.objects.create(user=request.user)
            user_profile.agent_profile = agent_profile
            user_profile.save()
            messages.success(request, "You are now an active agent!")
            return redirect("agent_dashboard")
        else:
            messages.error(request, "Insufficient wallet balance. Please load your wallet first.")
    return render(request, "become_agent.html", {
        "registration_fee": registration_fee,
        "user_profile": user_profile
    })


# -------------------
# Load wallet (Paystack initialize) and callback verification by reference
# -------------------
@login_required
def load_wallet(request):
    user_profile = request.user.userprofile
    if request.method == "POST":
        try:
            amount = float(request.POST.get("amount"))
            if amount <= 0:
                messages.error(request, "Enter a valid amount.")
                return redirect("load_wallet")

            callback_url = request.build_absolute_uri(reverse("wallet_callback"))
            headers = {
                "Authorization": f"Bearer {settings.PAYSTACK_SECRET_KEY}",
                "Content-Type": "application/json",
            }
            payload = {
                "email": request.user.email,
                "amount": int(amount * 100),
                "currency": "GHS",
                "callback_url": callback_url,
                "metadata": {"user_id": request.user.id, "type": "wallet_topup"}
            }
            response = requests.post("https://api.paystack.co/transaction/initialize", json=payload, headers=headers, timeout=15)
            res = response.json()
            if res.get("status"):
                return redirect(res["data"]["authorization_url"])
            messages.error(request, "Payment initialization failed. Try again.")
            return redirect("load_wallet")
        except Exception as e:
            messages.error(request, f"Error: {str(e)}")
            return redirect("load_wallet")
    return render(request, "load_wallet.html", {"wallet": user_profile.wallet})


@login_required
def wallet_callback(request):
    reference = request.GET.get("reference")
    if not reference:
        messages.error(request, "Invalid payment reference.")
        return redirect("load_wallet")

    headers = {"Authorization": f"Bearer {settings.PAYSTACK_SECRET_KEY}"}
    verify_url = f"https://api.paystack.co/transaction/verify/{reference}"
    try:
        response = requests.get(verify_url, headers=headers, timeout=15)
        res = response.json()
    except Exception:
        messages.error(request, "Error verifying transaction.")
        return redirect("load_wallet")

    try:
        if res.get("status") and res["data"]["status"] == "success":
            amount_paid = Decimal(res["data"]["amount"]) / 100
            user_profile = request.user.userprofile
            user_profile.wallet += amount_paid
            user_profile.save()
            messages.success(request, f"Wallet successfully credited with GHS {amount_paid:.2f}")
            return redirect("agent_dashboard")
        else:
            messages.error(request, "Transaction failed or incomplete.")
            return redirect("load_wallet")
    except Exception:
        messages.error(request, "Error processing payment verification.")
        return redirect("load_wallet")


# -------------------
# Paystack webhook (recommended): update wallets from webhook
# -------------------
@csrf_exempt
def paystack_webhook(request):
    """
    Paystack will POST event data here. We verify signature header if configured.
    This route should be configured on Paystack dashboard as a webhook endpoint.
    """
    try:
        payload = request.body
        sig = request.headers.get("x-paystack-signature") or request.META.get("HTTP_X_PAYSTACK_SIGNATURE")
        # If you have PAYSTACK_WEBHOOK_SECRET, verify HMAC
        secret = getattr(settings, "PAYSTACK_WEBHOOK_SECRET", None)
        if secret and sig:
            import hmac, hashlib
            computed = hmac.new(secret.encode(), payload, hashlib.sha512).hexdigest()
            if computed != sig:
                return render(request, "not_authorized.html", {"message": "Invalid webhook signature."}, status=403)

        data = json.loads(payload)
        event = data.get("event")
        if event == "charge.success":
            meta = data.get("data", {}).get("metadata", {})
            if meta.get("type") == "wallet_topup":
                user_id = meta.get("user_id")
                amount = Decimal(data["data"]["amount"]) / 100
                user = User.objects.filter(id=user_id).first()
                if user:
                    up, _ = UserProfile.objects.get_or_create(user=user)
                    up.wallet += amount
                    up.save()
        # reply 200 to acknowledge
        return render(request, "ok.html", {}, status=200)
    except Exception:
        return render(request, "not_authorized.html", {"message": "Webhook handling error."}, status=500)


# -------------------
# BUY BUNDLE (users buy bundles from admin bundles -> Smartdatalink order)
# changes: no quantity (single), recipient phone required
# -------------------
@login_required
def buy_bundle(request):
    profile = request.user.userprofile
    wallet_balance = profile.wallet

    # Admin bundles only (admin sets bundles)
    bundles_qs = Bundle.objects.filter(is_active=True).order_by("network", "name")
    bundles = [{
        "id": b.id,
        "name": b.name,
        "code": b.code,
        "network": b.network,
        "price": float(b.price),
        "send_via_api": b.send_via_api
    } for b in bundles_qs]

    if request.method == "POST":
        bundle_id = request.POST.get("bundle_id")
        recipient = request.POST.get("recipient")  # phone number
        if not bundle_id or not recipient:
            messages.error(request, "Select a bundle and provide recipient phone number.")
            return redirect("buy_bundle")

        # find bundle
        try:
            b = Bundle.objects.get(pk=int(bundle_id))
        except Exception:
            messages.error(request, "Selected bundle not found.")
            return redirect("buy_bundle")

        price = Decimal(str(b.price))
        # Check wallet
        if profile.wallet < price:
            messages.error(request, "Insufficient wallet balance.")
            return redirect("buy_bundle")

        # If bundle must be delivered via external Smartdatalink we call their API
        api_result = None
        order_success = False
        api_total_cost = None
        if getattr(settings, "SMART_BASE_URL", None) and b.send_via_api:
            # call Smartdatalink create order
            smart_url = settings.SMART_BASE_URL.rstrip("/") + "/create_order.php"
            payload = {
                "api_key": settings.SMART_API_KEY,
                "api_secret": settings.SMART_API_SECRET,
                "beneficiary": recipient,
                "package_size": b.code or b.name  # prefer code if it's package_size
            }
            try:
                r = requests.post(smart_url, json=payload, headers={"Authorization": f"Bearer {settings.SMART_API_KEY}", "Content-Type": "application/json"}, timeout=20)
                api_result = r.json()
                if api_result.get("status") == "success":
                    order_success = True
                    api_total_cost = Decimal(str(api_result.get("total_cost", price)))
                else:
                    order_success = False
            except Exception as e:
                order_success = False

            if not order_success:
                messages.error(request, f"Failed to process order with data provider. Try again later.")
                return redirect("buy_bundle")

        # Deduct from buyer wallet
        profile.wallet -= (api_total_cost if api_total_cost is not None else price)
        profile.save()

        # Save purchase record
        Purchase.objects.create(
            user=request.user,
            bundle=b,
            bundle_name=b.name,
            network=b.network,
            quantity=1,
            amount=(api_total_cost if api_total_cost is not None else price),
            recipient=recipient,
            status="PAID",
            created_at=timezone.now()
        )

        messages.success(request, f"Order placed for {b.name} to {recipient}.")
        return redirect("purchases")

    # GET view
    return render(request, "buy_bundle.html", {
        "wallet": wallet_balance,
        "bundles": bundles
    })


# -------------------
# SELL BUNDLE (agent-only). Agents can sell bundles to customer numbers.
# When sold, we create Purchase (order) and optional Sale record.
# -------------------
@login_required
def sell_bundle(request):
    profile = request.user.userprofile
    if not profile.is_agent:
        messages.error(request, "You need to become an agent first.")
        return redirect("agent_dashboard")

    bundles_qs = Bundle.objects.filter(is_active=True).order_by("network", "name")
    bundles = [{
        "id": b.id,
        "name": b.name,
        "code": b.code,
        "network": b.network,
        "price": float(b.price),
        "send_via_api": b.send_via_api
    } for b in bundles_qs]

    if request.method == "POST":
        bundle_id = request.POST.get("bundle_id")
        customer_phone = request.POST.get("customer_phone")
        if not bundle_id or not customer_phone:
            messages.error(request, "Select a bundle and provide customer phone number.")
            return redirect("sell_bundle")

        b = get_object_or_404(Bundle, pk=int(bundle_id))
        price = Decimal(str(b.price))

        # Agents sell: we create order via API if needed
        order_success = True
        api_total_cost = None
        if getattr(settings, "SMART_BASE_URL", None) and b.send_via_api:
            smart_url = settings.SMART_BASE_URL.rstrip("/") + "/create_order.php"
            payload = {
                "api_key": settings.SMART_API_KEY,
                "api_secret": settings.SMART_API_SECRET,
                "beneficiary": customer_phone,
                "package_size": b.code or b.name
            }
            try:
                r = requests.post(smart_url, json=payload, headers={"Authorization": f"Bearer {settings.SMART_API_KEY}", "Content-Type": "application/json"}, timeout=20)
                api_result = r.json()
                if api_result.get("status") == "success":
                    api_total_cost = Decimal(str(api_result.get("total_cost", price)))
                    order_success = True
                else:
                    order_success = False
            except Exception:
                order_success = False

            if not order_success:
                messages.error(request, "Failed to process API order. Try again.")
                return redirect("sell_bundle")

        # Create purchase record (agent performed a sale)
        purchase_amount = api_total_cost if api_total_cost is not None else price
        Purchase.objects.create(
            user=request.user,
            bundle=b,
            bundle_name=b.name,
            network=b.network,
            quantity=1,
            amount=purchase_amount,
            recipient=customer_phone,
            status="PAID",
            created_at=timezone.now()
        )

        # create Sale record too for agent analytics
        Sale.objects.create(
            agent=request.user,
            bundle=b,
            price=purchase_amount,
            quantity=1
        )

        messages.success(request, f"Sold {b.name} to {customer_phone}.")
        return redirect("agent_dashboard")

    return render(request, "sell_bundle.html", {"bundles": bundles})


# -------------------
# Contact Admin (display + message form)
# -------------------
@login_required
def contact_admin(request):
    admin_email = "richmondobeng2004@gmail.com"
    admin_whatsapp = "+233 55 637 3440"

    if request.method == "POST":
        subject = request.POST.get("subject")
        message_text = request.POST.get("message")
        if subject and message_text:
            ContactMessage.objects.create(
                user=request.user,
                email=request.user.email,
                subject=subject,
                message=message_text
            )
            messages.success(request, "Your message has been sent to admin.")
            return redirect("contact_admin")
        else:
            messages.error(request, "Please fill in all fields.")

    context = {
        "admin_email": admin_email,
        "admin_whatsapp": admin_whatsapp,
    }
    return render(request, "contact_admin.html", context)


# -------------------
# Admin views (simple) - view messages, set bundles, fund agent, etc.
# We'll protect with superuser check.
# -------------------
def is_admin(user):
    return user.is_superuser


@user_passes_test(is_admin)
def admin_dashboard(request):
    # aggregate metrics
    total_agents = UserProfile.objects.filter(is_agent=True).count()
    total_wallets = UserProfile.objects.aggregate(total=models.Sum('wallet'))['total'] or Decimal("0.00")
    total_orders_today = Purchase.objects.filter(created_at__date=timezone.now().date()).count()
    bundles = Bundle.objects.all().order_by("network", "name")
    contact_messages = ContactMessage.objects.all().order_by("-created_at")[:30]

    context = {
        "total_agents": total_agents,
        "total_wallets": total_wallets,
        "total_orders_today": total_orders_today,
        "bundles": bundles,
        "contact_messages": contact_messages,
    }
    return render(request, "admin_dashboard.html", context)


# -------------------
# Admin: Add / Edit Bundle (basic endpoints)
# Protected by superuser decorator
# -------------------
@user_passes_test(is_admin)
def admin_add_bundle(request):
    if request.method == "POST":
        name = request.POST.get("name")
        code = request.POST.get("code")
        network = request.POST.get("network")
        price = float(request.POST.get("price") or 0)
        send_via_api = bool(request.POST.get("send_via_api"))
        Bundle.objects.create(name=name, code=code, network=network, price=price, send_via_api=send_via_api, is_active=True)
        messages.success(request, "Bundle added.")
        return redirect("admin_dashboard")
    return render(request, "admin_add_bundle.html", {})


@user_passes_test(is_admin)
def admin_update_agent_wallet(request):
    """
    Admin can add/deduct funds from agent's wallet by email.
    POST params:
      - email
      - amount (positive for add, negative for deduct)
      - reason (optional)
    """
    if request.method == "POST":
        email = request.POST.get("email")
        amount = Decimal(request.POST.get("amount", "0"))
        user = User.objects.filter(email=email).first()
        if not user:
            messages.error(request, "User not found.")
            return redirect("admin_dashboard")
        profile, _ = UserProfile.objects.get_or_create(user=user)
        profile.wallet += amount
        profile.save()
        messages.success(request, f"Updated wallet for {user.email}. New balance: GHS {profile.wallet:.2f}")
        return redirect("admin_dashboard")
    return render(request, "admin_update_agent_wallet.html", {})

@user_passes_test(lambda u: u.is_superuser)
def admin_set_registration_fee(request):
    # get current registration fee from AppSettings
    settings, _ = AppSettings.objects.get_or_create(id=1)  # or first()
    
    if request.method == "POST":
        fee = request.POST.get("agent_registration_fee")
        try:
            fee = float(fee)
            settings.agent_registration_fee = fee
            settings.save()
            messages.success(request, f"Agent registration fee updated to GHS {fee:.2f}")
            return redirect("admin_dashboard")
        except ValueError:
            messages.error(request, "Invalid fee entered. Please enter a number.")
    
    context = {"current_fee": settings.agent_registration_fee or 0}
    return render(request, "admin_set_registration_fee.html", context)
