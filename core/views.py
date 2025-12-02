# core/views.py
from django.db import models
from decimal import Decimal
import json
import requests  # make sure 'requests' is installed in your environment

from django.conf import settings
from django.contrib import messages
from django.contrib.admin.views.decorators import staff_member_required
from django.contrib.auth import authenticate, login as auth_login, logout
from django.contrib.auth.decorators import login_required
from django.db.models import Sum
from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse
from django.utils.timezone import now, timezone
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.core.mail import send_mail
from core.models import UserProfile
import uuid
from .paystack_utils import paystack_initialize
import secrets
from .models import UserProfile, WalletTransaction


from django.contrib.auth.models import User
from core.models import (
    UserProfile,
    AgentProfile,
    Bundle,
    Purchase,
    AppSettings,
    Sale,
    ContactMessage
)


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

# ---------------------------
# API DOCS VIEW
# ---------------------------
@login_required
def api_docs(request):
    profile = request.user.userprofile
    agent = profile.agent_profile

    if not profile.is_agent:
        return render(request, "not_authorized.html", {"message": "Only agents can access API docs."})

    if not agent:
        return render(request, "not_authorized.html", {"message": "Your agent profile is missing."})

    if not agent.has_paid:
        return render(request, "api_docs_locked.html", {
            "message": "You must pay the agent registration fee before generating API keys."
        })

    return render(request, "api_docs.html", {
        "public_key": agent.public_key,
        "secret_key": agent.secret_key,
        "base_url": "https://richdatabundle-v3.onrender.com/api/",
        "endpoints": [
            {
                "name": "Buy Data",
                "url": "/v1/data/purchase/",
                "method": "POST",
                "description": "Purchase a single data bundle."
            },
            {
                "name": "Check Balance",
                "url": "/v1/wallet/balance/",
                "method": "GET",
                "description": "Get wallet balance using Secret Key."
            },
            {
                "name": "Verify Transaction",
                "url": "/v1/transactions/verify/",
                "method": "GET",
                "description": "Verify any purchase or wallet funding."
            },
        ]
    })


# ---------------------------
# GENERATE KEYS (NO PAGE)
# ---------------------------
@login_required
def generate_api_keys(request):
    profile = request.user.userprofile
    agent = profile.agent_profile

    if not profile.is_agent:
        return JsonResponse({"success": False, "message": "Not an agent."})

    if not agent:
        return JsonResponse({"success": False, "message": "Agent profile missing."})

    if not agent.has_paid:
        return JsonResponse({"success": False, "message": "You must pay the registration fee."})

    agent.generate_keys()

    return JsonResponse({
        "success": True,
        "public_key": agent.public_key,
        "secret_key": agent.secret_key
    })

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
    admin_whatsapp = "+233537204692"  # updated number in international format

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
# Helper
# -------------------
def is_admin(user):
    return user.is_superuser


# ----------------------------------
# 1. ADMIN DASHBOARD
# ----------------------------------
@staff_member_required(login_url="/admin/login/")
def admin_dashboard(request):
    total_agents = AgentProfile.objects.count()

    total_wallets = Decimal("0.00")
    for p in UserProfile.objects.all():
        total_wallets += getattr(p, "wallet", 0)

    total_orders_today = Purchase.objects.filter(created_at__date=now().date()).count()
    bundles = Bundle.objects.all().order_by("network", "name")
    contact_messages = ContactMessage.objects.all().order_by("-created_at")[:40]

    active_fee = AppSettings.objects.first()

    return render(request, "admin_dashboard.html", {
        "total_agents": total_agents,
        "total_wallets": total_wallets,
        "total_orders_today": total_orders_today,
        "bundles": bundles,
        "contact_messages": contact_messages,
        "active_fee": active_fee,
    })
# ---------------------------
# FUND AGENT WALLET
# ---------------------------
@staff_member_required(login_url='/admin/login/')
def admin_update_agent_wallet(request):
    agent_data = None

    # SEARCH AGENT BY EMAIL
    email = request.GET.get("search_email")
    if email:
        try:
            profile = UserProfile.objects.get(user__email=email, is_agent=True)
            agent_data = profile
        except UserProfile.DoesNotExist:
            messages.error(request, "No agent found with that email.")

    # FUND WALLET
    if request.method == "POST":
        email = request.POST.get("email")
        amount = Decimal(request.POST.get("amount", "0"))
        reason = request.POST.get("reason", "Admin wallet top-up")

        if amount <= 0:
            messages.error(request, "Invalid amount.")
            return redirect("admin_update_agent_wallet")

        try:
            profile = UserProfile.objects.get(user__email=email, is_agent=True)
        except UserProfile.DoesNotExist:
            messages.error(request, "Agent not found.")
            return redirect("admin_update_agent_wallet")

        # PAYSTACK TRANSFER FROM ADMIN BALANCE
        headers = {
            "Authorization": f"Bearer {settings.PAYSTACK_SECRET_KEY}",
            "Content-Type": "application/json"
        }
        payload = {
            "source": "balance",
            "reason": reason,
            "amount": int(amount * 100),  # convert to pesewas
            "recipient": settings.AGENT_PAYSTACK_RECIPIENT,
            "currency": "GHS"
        }
        try:
            r = requests.post("https://api.paystack.co/transfer", json=payload, headers=headers, timeout=10)
            res = r.json()
            if not res.get("status"):
                messages.error(request, f"Paystack Error: {res.get('message')}")
                return redirect("admin_update_agent_wallet")
        except Exception as e:
            messages.error(request, f"Paystack API error: {str(e)}")
            return redirect("admin_update_agent_wallet")

        # Update Wallet Locally
        profile.wallet += amount
        profile.save()

        WalletTransaction.objects.create(
            user=profile.user,
            transaction_type="FUND",
            amount=amount,
            reason=reason,
            performed_by=request.user,
            success=True
        )

        send_wallet_alert(profile.user, amount, "CREDIT")
        messages.success(request, f"Successfully funded GHS {amount} to {profile.user.email}")
        return redirect(f"{reverse('admin_update_agent_wallet')}?search_email={email}")

    return render(request, "admin_update_agent_wallet.html", {"agent_data": agent_data})


# ---------------------------
# DEDUCT AGENT WALLET
# ---------------------------
@staff_member_required(login_url='/admin/login/')
def admin_deduct_agent_wallet(request):
    agent_data = None

    # SEARCH AGENT BY EMAIL
    email = request.GET.get("search_email")
    if email:
        try:
            profile = UserProfile.objects.get(user__email=email, is_agent=True)
            agent_data = profile
        except UserProfile.DoesNotExist:
            messages.error(request, "No agent found with that email.")

    # DEDUCT WALLET
    if request.method == "POST":
        email = request.POST.get("email")
        amount = Decimal(request.POST.get("amount", "0"))
        reason = request.POST.get("reason", "Admin deduction")

        if amount <= 0:
            messages.error(request, "Invalid amount.")
            return redirect("admin_deduct_agent_wallet")

        try:
            profile = UserProfile.objects.get(user__email=email, is_agent=True)
        except UserProfile.DoesNotExist:
            messages.error(request, "Agent not found.")
            return redirect("admin_deduct_agent_wallet")

        # Create transaction locally first
        reference = f"ADM_DED_{uuid.uuid4().hex[:12].upper()}"
        tx = WalletTransaction.objects.create(
            user=profile.user,
            transaction_type="DEDUCT",
            amount=amount,
            reason=reason,
            performed_by=request.user,
            reference=reference,
            success=False
        )

        # Initialize Paystack transfer
        callback_url = request.build_absolute_uri(reverse("paystack_deduct_callback"))
        payload = {
            "amount": int(amount * 100),
            "recipient": settings.AGENT_PAYSTACK_RECIPIENT,
            "reason": reason,
            "source": "balance"
        }
        headers = {"Authorization": f"Bearer {settings.PAYSTACK_SECRET_KEY}", "Content-Type": "application/json"}
        try:
            r = requests.post("https://api.paystack.co/transfer", json=payload, headers=headers, timeout=10)
            res = r.json()
            if not res.get("status"):
                messages.error(request, f"Paystack Error: {res.get('message')}")
                return redirect("admin_deduct_agent_wallet")
        except Exception as e:
            messages.error(request, f"Paystack API error: {str(e)}")
            return redirect("admin_deduct_agent_wallet")

        # Deduct locally
        profile.wallet -= amount
        profile.save()
        tx.success = True
        tx.save()
        send_wallet_alert(profile.user, amount, "DEBIT")
        messages.success(request, f"Successfully deducted GHS {amount} from {profile.user.email}")
        return redirect(f"{reverse('admin_deduct_agent_wallet')}?search_email={email}")

    return render(request, "admin_deduct_agent_wallet.html", {"agent_data": agent_data})



# ---------------------------
# AGENT AUTOCOMPLETE API
# ---------------------------
@staff_member_required(login_url='/admin/login/')
def agent_autocomplete(request):
    q = request.GET.get("q", "").strip()
    if not q:
        return JsonResponse({"results": []})

    users = User.objects.filter(userprofile__is_agent=True, email__icontains=q)[:10]
    results = [{"email": u.email, "username": u.username, "id": u.id} for u in users]
    return JsonResponse({"results": results})


# ----------------

# LIVE WALLET BALANCE
@login_required
def live_wallet_balance(request, user_id):
    profile = get_object_or_404(UserProfile, user__id=user_id)
    return JsonResponse({"wallet": float(profile.wallet)})


# ---------------------------
# SEND WALLET ALERT (EMAIL)
# ---------------------------
def send_wallet_alert(user, amount, tx_type):
    subject = f"Wallet {'Credit' if tx_type=='CREDIT' else 'Debit'} Alert"
    message = (
        f"Hello {user.username},\n\n"
        f"Your wallet was {'credited' if tx_type=='CREDIT' else 'debited'} "
        f"₵{amount}.\n\nYour new balance is: ₵{user.userprofile.wallet}\n"
    )
    send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email], fail_silently=True)
    # SMS stub: send_sms(user.phone, message)


    # SMS (Stub - replace with actual SMS provider)
    # send_sms(user.phone, message)

@staff_member_required(login_url='/admin/login/')
def admin_wallet_transactions(request):
    qs = WalletTransaction.objects.all()

    # FILTERS
    if request.GET.get("email"):
        qs = qs.filter(user__email__icontains=request.GET["email"])

    if request.GET.get("type"):
        qs = qs.filter(transaction_type=request.GET["type"])

    if request.GET.get("date_from"):
        qs = qs.filter(created_at__gte=request.GET["date_from"])

    if request.GET.get("date_to"):
        qs = qs.filter(created_at__lte=request.GET["date_to"])

    return render(request, "admin_wallet_transactions.html", {
        "transactions": qs
    })


# ----------------------------------
# 2. VIEW & MANAGE AGENTS
# ----------------------------------

# ---------------------------
# Admin Agents List
# ---------------------------
@staff_member_required(login_url="/admin/login/")
def admin_agents(request):
    agents = UserProfile.objects.filter(is_agent=True).select_related("user", "agent_profile")
    agent_data = []

    for p in agents:
        ag = p.agent_profile
        agent_data.append({
            "user": p.user,
            "profile": p,
            "agent": ag,
            "wallet": p.wallet,
            "sales": ag.total_sales if ag else 0,
            "volume": ag.total_sales_volume if ag else 0
        })

    return render(request, "admin_agents.html", {"agent_data": agent_data})

# ---------------------------
# Promote Agent to Staff/Admin
# ---------------------------
@staff_member_required(login_url="/admin/login/")
def admin_make_staff(request, user_id):
    user = get_object_or_404(User, id=user_id)
    user.is_staff = True
    user.save()
    messages.success(request, f"{user.username} is now a Staff/Admin.")
    return redirect("admin_agents")

# ---------------------------
# Delete Agent
# ---------------------------
@staff_member_required(login_url="/admin/login/")
def admin_delete_agent(request, user_id):
    user = get_object_or_404(User, id=user_id)

    # Remove agent profile if exists
    if hasattr(user, "userprofile"):
        if user.userprofile.agent_profile:
            user.userprofile.agent_profile.delete()
        user.userprofile.is_agent = False
        user.userprofile.agent_profile = None
        user.userprofile.save()

    user.is_staff = False
    user.save()

    messages.success(request, "Agent deleted successfully.")
    return redirect("admin_agents")

# ----------------------------------
# 3. WALLET OVERVIEW
# ----------------------------------
@staff_member_required(login_url="/admin/login/")
def admin_wallets(request):
    agents = AgentProfile.objects.select_related("user")

    wallet_list = []
    total_wallet_funds = Decimal("0.00")

    for ag in agents:
        profile = getattr(ag.user, "userprofile", None)
        balance = getattr(profile, "wallet", 0)
        total_wallet_funds += balance

        wallet_list.append({
            "agent": ag,
            "user": ag.user,
            "wallet_balance": balance,
        })

    return render(request, "admin_wallets.html", {
        "agents": wallet_list,
        "total_wallet_funds": total_wallet_funds
    })


# ----------------------------------
# 4. ORDER HISTORY (FULL)
# ----------------------------------
@staff_member_required(login_url="/admin/login/")
def admin_orders(request):
    show_all = request.GET.get("all") == "1"

    if show_all:
        orders = Purchase.objects.all().select_related("user", "bundle").order_by("-created_at")
    else:
        orders = Purchase.objects.filter(created_at__date=now().date()) \
            .select_related("user", "bundle").order_by("-created_at")

    return render(request, "admin_orders_today.html", {
        "orders": orders,
        "today": now().date(),
        "show_all": show_all,
    })


# ----------------------------------
# 5. ADD / EDIT / DELETE BUNDLE
# ----------------------------------
@staff_member_required(login_url="/admin/login/")
def admin_add_bundle(request):
    if request.method == "POST":
        Bundle.objects.create(
            name=request.POST["name"],
            code=request.POST["code"],
            network=request.POST["network"],
            price=float(request.POST["price"]),
            send_via_api=request.POST.get("send_via_api") == "on",
            is_active=True
        )

        messages.success(request, "Bundle added successfully.")
        return redirect("admin_dashboard")

    return render(request, "admin_add_bundle.html")


@staff_member_required(login_url="/admin/login/")
def admin_edit_bundle(request, bundle_id):
    bundle = get_object_or_404(Bundle, id=bundle_id)

    if request.method == "POST":
        bundle.name = request.POST["name"]
        bundle.code = request.POST["code"]
        bundle.price = float(request.POST["price"])
        bundle.network = request.POST["network"]
        bundle.send_via_api = request.POST.get("send_via_api") == "on"
        bundle.save()

        messages.success(request, "Bundle updated successfully.")
        return redirect("admin_dashboard")

    return render(request, "admin_edit_bundle.html", {
        "bundle": bundle
    })


@staff_member_required(login_url="/admin/login/")
def admin_delete_bundle(request, bundle_id):
    bundle = get_object_or_404(Bundle, id=bundle_id)
    bundle.delete()

    messages.success(request, "Bundle deleted successfully.")
    return redirect("admin_dashboard")


# ----------------------------------
# 6. DELETE CONTACT MESSAGE
# ----------------------------------
@staff_member_required(login_url="/admin/login/")
def admin_delete_message(request, message_id):
    msg = get_object_or_404(ContactMessage, id=message_id)
    msg.delete()
    messages.success(request, "Message deleted.")
    return redirect("admin_dashboard")


# ----------------------------------
# 7. REGISTRATION FEE WITH HISTORY
# ----------------------------------
@staff_member_required(login_url="/admin/login/")
def admin_set_registration_fee(request):
    settings_obj = AppSettings.objects.first()

    if request.method == "POST":
        fee = Decimal(request.POST.get("fee", 0))
        settings_obj.agent_registration_fee = fee
        settings_obj.save()

        messages.success(request, "Registration fee updated!")
        return redirect("admin_set_registration_fee")

    # NOW updated_at exists, so ordering works
    fee_history = AppSettings.objects.order_by("-updated_at")[:20]

    return render(request, "admin_set_registration_fee.html", {
        "settings": settings_obj,
        "fee_history": fee_history
    })
