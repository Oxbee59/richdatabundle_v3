# core/views.py
from django.db import models
from decimal import Decimal
import json
import requests  # make sure 'requests' is installed in your environment
import logging
from django.conf import settings
from django.contrib import messages
from django.contrib.admin.views.decorators import staff_member_required
from django.contrib.auth import authenticate, login as auth_login, logout
from django.contrib.auth.decorators import login_required
from django.db.models import Sum
from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse
from django.utils import timezone 
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.core.mail import send_mail
from core.models import UserProfile
import uuid
from .paystack_utils import paystack_initialize
import secrets
from .models import UserProfile, WalletTransaction
from django.db import transaction
from django.utils.timezone import now


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
# API DOCS VIEW (MAIN PAGE)
# ---------------------------
@login_required
def api_docs(request):
    profile = request.user.userprofile
    agent = profile.agent_profile

    # Only agents can view API docs
    if not profile.is_agent:
        return render(request, "not_authorized.html", {
            "message": "Only agents can access API documentation."
        })

    # Agent profile must exist
    if not agent:
        return render(request, "not_authorized.html", {
            "message": "Your agent profile is missing."
        })

    # Must pay before seeing/generating API keys
    if not agent.has_paid:
        return render(request, "api_docs_locked.html", {
            "message": "You must pay the agent registration fee before accessing API keys."
        })

    # MAIN API DOC CONTENT
    return render(request, "api_docs.html", {
        "public_key": agent.public_key,
        "secret_key": agent.secret_key,
        "base_url": "https://richdatabundle-v3.onrender.com/api/",

        # ---- DOCUMENTATION CARDS (REAL ENDPOINTS) ----
        "api_sections": [

            # ------------------
            # AUTHENTICATION
            # ------------------
            {
                "title": "Authentication",
                "description": "Authenticate using your Secret Key in the header.",
                "endpoints": [
                    {
                        "name": "Header Authentication",
                        "url": "ALL REQUESTS",
                        "method": "Header",
                        "description": "Send Secret Key as: Authorization: Bearer YOUR_SECRET_KEY",
                        "sample": {
                            "curl": "curl -H \"Authorization: Bearer SECRET_KEY\" https://richdatabundle-v3.onrender.com/api/v1/wallet/balance/"
                        }
                    }
                ]
            },

            # ------------------
            # DATA PURCHASE
            # ------------------
            {
                "title": "Data Purchase",
                "description": "Buy mobile data bundles for MTN, Airtel, Glo, 9mobile.",
                "endpoints": [
                    {
                        "name": "Buy Data",
                        "url": "v1/data/purchase/",
                        "method": "POST",
                        "description": "Purchase a single data bundle.",
                        "sample": {
                            "json": {
                                "network": "mtn",
                                "plan_id": "mtn-1gb-500",
                                "phone": "08012345678",
                                "reference": "unique-ref-001"
                            }
                        }
                    }
                ]
            },

            # ------------------
            # WALLET
            # ------------------
            {
                "title": "Wallet",
                "description": "View wallet details and available balance.",
                "endpoints": [
                    {
                        "name": "Check Wallet Balance",
                        "url": "v1/wallet/balance/",
                        "method": "GET",
                        "description": "Returns real-time wallet balance.",
                        "sample": {
                            "json_response": {
                                "success": True,
                                "balance": 3500.00
                            }
                        }
                    }
                ]
            },

            # ------------------
            # TRANSACTIONS
            # ------------------
            {
                "title": "Transactions",
                "description": "Verify and track purchases/wallet funding.",
                "endpoints": [
                    {
                        "name": "Verify Transaction",
                        "url": "v1/transactions/verify/",
                        "method": "GET",
                        "description": "Verify data purchase or wallet funding.",
                        "query_params": "?reference=your_ref",
                        "sample": {
                            "json_response": {
                                "status": "success",
                                "message": "Transaction verified",
                                "details": {}
                            }
                        }
                    }
                ]
            },

        ]
    })

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

    # generate new keys
    agent.generate_keys()

    return JsonResponse({
        "success": True,
        "public_key": agent.public_key,
        "secret_key": agent.secret_key
    })


#
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
# BUY BUNDLE (Final Version)
 
logger = logging.getLogger(__name__)


# ---------- Helper: fetch remote bundles with fallback ----------
def fetch_remote_bundles():
    base = getattr(settings, "SMART_BASE_URL", None)
    if not base:
        return None
    base = base.rstrip('/')
    # prefer documented endpoints - provider uses POST to create_order.php and lists via /packages.php or similar
    list_paths = ["/packages.php", "/bundles.php", "/api/packages.php", "/api/bundles.php", "/list_packages.php"]

    payload = {"api_key": settings.SMART_API_KEY, "api_secret": settings.SMART_API_SECRET}
    headers = {
        "Authorization": f"Bearer {settings.SMART_API_KEY}" if settings.SMART_API_KEY else "",
        "Content-Type": "application/json"
    }

    for path in list_paths:
        url = f"{base}{path}"
        try:
            r = requests.post(url, json=payload, headers=headers, timeout=12)
            logger.debug("fetch_remote_bundles: %s -> %s", url, r.text[:1000])
            data = r.json()
        except Exception as e:
            logger.debug("fetch_remote_bundles: request failed %s: %s", url, e)
            continue

        # success shapes seen in docs: status:'success' and 'packages'/'bundles' or top-level list
        if data.get("status") in ("success", True):
            candidates = data.get("packages") or data.get("bundles") or data.get("data") or data.get("results") or (data if isinstance(data, list) else None)
            if not candidates:
                continue

            packages = []
            for item in candidates:
                code = item.get("code") or item.get("id") or item.get("package") or item.get("package_size")
                name = item.get("name") or item.get("package_name") or code
                network = (item.get("network") or item.get("network_type") or item.get("provider") or "").upper()
                price = item.get("price") or item.get("amount") or item.get("cost") or 0.0
                try:
                    price = float(price)
                except Exception:
                    price = 0.0

                packages.append({
                    "code": str(code),
                    "name": str(name),
                    "network": str(network),
                    "price": price
                })

            if packages:
                return packages

    return None

def create_remote_order(package_code, beneficiary):
    """
    Calls SmartDataLink /create_order.php and returns dict with keys:
      success(bool), total_cost(Decimal), order_ids(list)|None, raw(response dict)
    """
    base = getattr(settings, "SMART_BASE_URL", "").rstrip('/')
    url = f"{base}/create_order.php"
    payload = {
        "api_key": settings.SMART_API_KEY,
        "api_secret": settings.SMART_API_SECRET,
        "beneficiary": beneficiary,
        "package_size": package_code
    }
    headers = {
        "Authorization": f"Bearer {settings.SMART_API_KEY}" if settings.SMART_API_KEY else "",
        "Content-Type": "application/json"
    }

    try:
        r = requests.post(url, json=payload, headers=headers, timeout=20)
        raw = r.json() if r.text else {}
    except requests.RequestException as e:
        logger.exception("create_remote_order: provider request failed")
        return {"success": False, "error": "provider-unreachable", "raw": {"error": str(e)}}

    # Interpret provider response per docs
    if raw.get("status") in ("success", True) or raw.get("processed", 0) > 0:
        # total_cost may be provided
        total_cost = raw.get("total_cost") or raw.get("amount") or 0
        try:
            total_cost = Decimal(str(total_cost))
        except Exception:
            total_cost = Decimal("0.00")
        return {"success": True, "total_cost": total_cost, "order_ids": raw.get("order_ids") or raw.get("order_id") or raw.get("order_ids", []), "raw": raw}
    else:
        # return provider message when possible
        message = raw.get("message") or raw.get("error") or str(raw)
        return {"success": False, "error": message, "raw": raw}


# ---------- BUY BUNDLE (updated) ----------
@login_required
@transaction.atomic
def buy_bundle(request):
    profile = request.user.userprofile
    wallet = profile.wallet

    # fetch remote packages; fallback to local DB bundles
    remote = fetch_remote_bundles()
    if remote:
        bundles = [{"id": p["code"], "name": p["name"], "code": p["code"], "network": p["network"], "price": p["price"], "send_via_api": True} for p in remote]
    else:
        bundles_qs = Bundle.objects.filter(is_active=True).order_by("network", "name")
        bundles = [{"id": b.id, "name": b.name, "code": b.vendor_code or b.code, "network": b.network, "price": float(b.price), "send_via_api": b.send_via_api} for b in bundles_qs]

    if request.method == "POST":
        selected = request.POST.get("bundle_id")
        recipient = request.POST.get("recipient")

        if not selected or not recipient:
            messages.error(request, "Select a bundle and enter recipient phone.")
            return redirect("buy_bundle")

        # Resolve bundle: remote uses package code; local uses numeric id
        using_remote = False
        b_obj = None
        if remote:
            for p in remote:
                if selected == p["code"] or selected == p["name"]:
                    using_remote = True
                    package_code = p["code"]
                    bundle_name = p["name"]
                    network = p["network"]
                    price = Decimal(str(p["price"]))
                    break
            else:
                # maybe user selected a local bundle id
                try:
                    b_local = Bundle.objects.get(pk=int(selected))
                    package_code = b_local.vendor_code or b_local.code
                    bundle_name = b_local.name
                    network = b_local.network
                    price = b_local.price
                except Exception:
                    messages.error(request, "Selected bundle not found.")
                    return redirect("buy_bundle")
        else:
            try:
                b_local = Bundle.objects.get(pk=int(selected))
                package_code = b_local.vendor_code or b_local.code
                bundle_name = b_local.name
                network = b_local.network
                price = b_local.price
            except Exception:
                messages.error(request, "Selected bundle not found.")
                return redirect("buy_bundle")

        # wallet check (user/agent)
        if profile.wallet < price:
            messages.error(request, "Insufficient wallet balance.")
            return redirect("buy_bundle")

        # Call provider only if send_via_api true (remote packages are always API)
        if using_remote or (not using_remote and getattr(b_local, "send_via_api", False)):
            result = create_remote_order(package_code, recipient)
            if not result.get("success"):
                messages.error(request, f"Provider failed: {result.get('error')}")
                # optionally record a failed Purchase here with response_data=result['raw']
                return redirect("buy_bundle")

            api_cost = result.get("total_cost", price)
            # Deduct user wallet only after success
            profile.wallet -= Decimal(api_cost)
            profile.save()

            # Save purchase with provider response
            Purchase.objects.create(
                user=request.user,
                bundle=None if using_remote else b_local,
                bundle_name=bundle_name,
                network=network,
                quantity=1,
                amount=api_cost,
                recipient=recipient,
                source="API",
                transaction_reference=(result.get("order_ids") and (result["order_ids"][0] if isinstance(result["order_ids"], (list,tuple)) else result["order_ids"])) or None,
                response_data=result.get("raw"),
                status="PAID"
            )

        else:
            # Local delivery path (admin deliverable)
            profile.wallet -= price
            profile.save()
            Purchase.objects.create(
                user=request.user,
                bundle=b_local,
                bundle_name=b_local.name,
                network=b_local.network,
                quantity=1,
                amount=price,
                recipient=recipient,
                source="ADMIN",
                status="PAID"
            )

        messages.success(request, f"{bundle_name} sent to {recipient}. GHS {api_cost if 'api_cost' in locals() else price} deducted.")
        return redirect("purchases")

    return render(request, "buy_bundle.html", {"wallet": wallet, "bundles": bundles})

# ---------- SELL BUNDLE (updated) ----------
@login_required
@transaction.atomic
def sell_bundle(request):
    profile = request.user.userprofile

    if not profile.is_agent:
        messages.error(request, "You must be an agent to sell bundles.")
        return redirect("agent_dashboard")

    # fetch remote bundles first
    remote = fetch_remote_bundles()
    if remote:
        bundles = [{
            "id": p["code"],  # package code
            "name": p["name"],
            "code": p["code"],
            "network": p["network"],
            "price": p["price"],
            "send_via_api": True
        } for p in remote]
    else:
        bundles_qs = Bundle.objects.filter(is_active=True).order_by("network", "name")
        bundles = [{
            "id": b.id,
            "name": b.name,
            "code": b.vendor_code or b.code,
            "network": b.network,
            "price": float(b.price),
            "send_via_api": b.send_via_api
        } for b in bundles_qs]

    if request.method == "POST":
        selected = request.POST.get("bundle_id")
        phone = request.POST.get("customer_phone")

        if not selected or not phone:
            messages.error(request, "Select a bundle and enter customer phone.")
            return redirect("sell_bundle")

        using_remote = False
        if remote:
            for p in remote:
                if selected == p["code"] or selected == p["name"]:
                    using_remote = True
                    package_code = p["code"]
                    bundle_name = p["name"]
                    network = p["network"]
                    price = Decimal(str(p["price"]))
                    break
            else:
                try:
                    b_local = Bundle.objects.get(pk=int(selected))
                    package_code = b_local.vendor_code or b_local.code
                    bundle_name = b_local.name
                    network = b_local.network
                    price = b_local.price
                except Exception:
                    messages.error(request, "Selected bundle not found.")
                    return redirect("sell_bundle")
        else:
            try:
                b_local = Bundle.objects.get(pk=int(selected))
                package_code = b_local.vendor_code or b_local.code
                bundle_name = b_local.name
                network = b_local.network
                price = b_local.price
            except Exception:
                messages.error(request, "Selected bundle not found.")
                return redirect("sell_bundle")

        if profile.wallet < price:
            messages.error(request, "Insufficient wallet balance.")
            return redirect("sell_bundle")

        # always API for remote bundles
        if using_remote or (not using_remote and getattr(b_local, "send_via_api", False)):
            result = create_remote_order(package_code, phone)
            if not result.get("success"):
                messages.error(request, f"Provider failed: {result.get('error')}")
                return redirect("sell_bundle")

            api_cost = result.get("total_cost", price)

            profile.wallet -= api_cost
            profile.save()

            Purchase.objects.create(
                user=request.user,
                bundle=None if using_remote else b_local,
                bundle_name=bundle_name,
                network=network,
                quantity=1,
                amount=api_cost,
                recipient=phone,
                source="API",
                transaction_reference=(
                    result.get("order_ids")[0]
                    if isinstance(result.get("order_ids"), list) and result["order_ids"]
                    else result.get("order_ids")
                ),
                response_data=result.get("raw"),
                status="PAID"
            )

            Sale.objects.create(
                agent=request.user,
                bundle=None if using_remote else b_local,
                price=api_cost,
                quantity=1
            )

        else:
            profile.wallet -= price
            profile.save()

            Purchase.objects.create(
                user=request.user,
                bundle=b_local,
                bundle_name=b_local.name,
                network=b_local.network,
                quantity=1,
                amount=price,
                recipient=phone,
                source="ADMIN",
                status="PAID"
            )

        messages.success(request, f"Sold {bundle_name} to {phone}. GHS {api_cost if 'api_cost' in locals() else price} deducted.")
        return redirect("sell_bundle")

    return render(request, "sell_bundle.html", {
        "bundles": bundles,
        "wallet_balance": profile.wallet
    })


    
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
        messages.success(
            request,
            f"Successfully funded GHS {amount} to {profile.user.email}. Current balance: GHS {profile.wallet}"
        )
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

        if profile.wallet < amount:
            messages.error(request, f"Cannot deduct GHS {amount}. Agent balance is only GHS {profile.wallet}")
            return redirect(f"{reverse('admin_deduct_agent_wallet')}?search_email={email}")

        # Deduct locally
        profile.wallet -= amount
        profile.save()

        WalletTransaction.objects.create(
            user=profile.user,
            transaction_type="DEDUCT",
            amount=amount,
            reason=reason,
            performed_by=request.user,
            success=True
        )

        send_wallet_alert(profile.user, amount, "DEBIT")
        messages.success(
            request,
            f"Successfully deducted GHS {amount} from {profile.user.email}. Current balance: GHS {profile.wallet}"
        )
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
            name=request.POST.get("name"),
            vendor_code=request.POST.get("vendor_code"),
            network=request.POST.get("network"),
            price=Decimal(request.POST.get("price")),
            vendor_price=Decimal(request.POST.get("vendor_price") or 0),
            bundle_type=request.POST.get("bundle_type"),
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
        bundle.name = request.POST.get("name")
        bundle.vendor_code = request.POST.get("vendor_code")
        bundle.network = request.POST.get("network")
        bundle.price = Decimal(request.POST.get("price"))
        bundle.vendor_price = Decimal(request.POST.get("vendor_price") or 0)
        bundle.bundle_type = request.POST.get("bundle_type")
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
