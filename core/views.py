from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login as auth_login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .models import UserProfile, AgentProfile, Bundle, Purchase, AppSettings
from django.contrib.auth.models import User
from django.shortcuts import render
from .models import Settings  # assuming you have a Settings model for admin configs
from .models import Bundle, Purchase, UserProfile, AgentProfile, Sale
from .models import Bundle, Sale, UserProfile, AgentProfile
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from decimal import Decimal
from django.utils import timezone
from django.urls import reverse
import requests
from .models import AgentProfile, Withdrawal

# -------------------
# SIGNUP
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

# -------------------
# LOGIN
# -------------------
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


# -------------------
# LOGOUT VIEW
# -------------------
def logout_user(request):
    logout(request)
    return redirect("login")


@login_required
def agent_dashboard(request):
    user = request.user
    profile, _ = UserProfile.objects.get_or_create(user=user)
    agent_profile, _ = AgentProfile.objects.get_or_create(user=user)

    # Agent metrics
    wallet_balance = profile.wallet
    commission = agent_profile.commission_earned
    total_sales_count = agent_profile.total_sales
    total_sales_volume = agent_profile.total_sales_volume

    # Recent purchases for this agent/user
    recent_sales = Purchase.objects.filter(user=user).order_by("-created_at")[:10]

    # All bundles (local + API-marked)
    bundles = Bundle.objects.all()

    # App settings
    app_settings = AppSettings.objects.first()

    context = {
        "wallet_balance": wallet_balance,
        "commission": commission,
        "total_sales_count": total_sales_count,
        "total_sales_volume": total_sales_volume,
        "recent_sales": recent_sales,
        "bundles": bundles,
        "api_key": agent_profile.api_key,
        "app_settings": app_settings,
        "user_name": user.username,  # for sidebar display
    }
    return render(request, "agent_dashboard.html", context)

@login_required
def profile(request):
    profile, _ = UserProfile.objects.get_or_create(user=request.user)
    return render(request, "profile.html", {"profile": profile})


@login_required
def purchases(request):
    user_purchases = Purchase.objects.filter(user=request.user).order_by("-created_at")

    return render(request, "purchases.html", {
        "purchases": user_purchases
    })


@login_required
def api_docs(request):
    # Only registered agents can see
    if not request.user.userprofile.is_agent:
        return render(request, "not_authorized.html", {"message": "You must be an agent to access the API."})

    context = {
        "api_key": request.user.userprofile.api_key,  # unique agent API key
        "base_url": "https://yourdomain.com/api/",
        "endpoints": [
            {"name": "Check Balance", "url": "/api/wallet/", "method": "GET", "description": "Check your wallet balance."},
            {"name": "Sell Bundle", "url": "/api/sell-bundle/", "method": "POST", "description": "Sell bundle to customer."},
            {"name": "Purchase History", "url": "/api/purchases/", "method": "GET", "description": "Get all your past purchases."},
        ]
    }
    return render(request, "api_docs.html", context)

@login_required
def become_agent(request):
    user_profile = request.user.userprofile

    # Get registration fee set by admin
    registration_fee_setting = Settings.objects.filter(key='agent_registration_fee').first()
    registration_fee = float(registration_fee_setting.value) if registration_fee_setting else 50.0  # default fee

    if user_profile.is_agent:
        messages.info(request, "You are already an agent.")
        return redirect("/agent-dashboard/")

    if request.method == "POST":
        if user_profile.wallet >= registration_fee:
            # Deduct fee
            user_profile.wallet -= registration_fee
            user_profile.is_agent = True
            # Create AgentProfile
            agent_profile = AgentProfile.objects.create(user=request.user)
            user_profile.agent_profile = agent_profile
            user_profile.save()
            messages.success(request, "You are now an active agent!")
            return redirect("/agent-dashboard/")
        else:
            messages.error(request, "Insufficient wallet balance. Please load your wallet first.")

    return render(request, "become_agent.html", {
        "registration_fee": registration_fee,
        "user_profile": user_profile
    })

@login_required
def load_wallet(request):
    user_profile = request.user.userprofile

    if request.method == "POST":
        try:
            amount = float(request.POST.get("amount"))
            if amount <= 0:
                messages.error(request, "Enter a valid amount.")
                return redirect("load_wallet")

            # Build callback URL
            callback_url = request.build_absolute_uri(reverse("wallet_callback"))

            # Paystack headers
            headers = {
                "Authorization": f"Bearer {settings.PAYSTACK_SECRET_KEY}",
                "Content-Type": "application/json",
            }

            # Paystack payload
            payload = {
                "email": request.user.email,
                "amount": int(amount * 100),  # Paystack uses kobo
                "currency": "GHS",
                "callback_url": callback_url,

                # VERY IMPORTANT — to identify the wallet owner
                "metadata": {
                    "user_id": request.user.id,
                    "type": "wallet_topup",
                }
            }

            # Initialize transaction
            response = requests.post(
                "https://api.paystack.co/transaction/initialize",
                json=payload,
                headers=headers
            )
            res = response.json()

            if res.get("status") is True:
                # Redirect user to Paystack payment page
                return redirect(res["data"]["authorization_url"])

            messages.error(request, "Payment initialization failed. Try again.")
            return redirect("load_wallet")

        except Exception as e:
            messages.error(request, f"Error: {str(e)}")
            return redirect("load_wallet")

    return render(request, "load_wallet.html", {
        "wallet": user_profile.wallet
    })


@login_required
def wallet_callback(request):
    reference = request.GET.get("reference")
    if not reference:
        messages.error(request, "Invalid payment reference.")
        return redirect("load_wallet")

    # Verify payment with Paystack
    headers = {
        "Authorization": f"Bearer {settings.PAYSTACK_SECRET_KEY}",
    }

    verify_url = f"https://api.paystack.co/transaction/verify/{reference}"
    response = requests.get(verify_url, headers=headers)
    res = response.json()

    try:
        if res["status"] and res["data"]["status"] == "success":
            amount_paid = res["data"]["amount"] / 100  # convert kobo → GHS

            user_profile = request.user.userprofile
            user_profile.wallet += amount_paid
            user_profile.save()

            messages.success(
                request,
                f"Wallet successfully credited with GHS {amount_paid:.2f}"
            )
            return redirect("agent_dashboard")

        else:
            messages.error(request, "Transaction failed or incomplete.")
            return redirect("load_wallet")

    except Exception:
        messages.error(request, "Error verifying transaction.")
        return redirect("load_wallet")

@login_required
def buy_bundle(request):
    user_profile = request.user.userprofile
    wallet_balance = user_profile.wallet

    # HEADERS FOR API
    headers = {"Authorization": f"Bearer {settings.DATA_API_KEY}"}

    # ---- FETCH API BUNDLES ----
    api_bundles = []
    try:
        response = requests.get(
            f"{settings.DATA_API_BASE_URL}bundles?user_id={settings.DATA_API_USER_ID}",
            headers=headers,
            timeout=10
        )
        response.raise_for_status()
        api_data = response.json().get("bundles", [])

        # Normalize to match local bundle structure
        for b in api_data:
            api_bundles.append({
                "id": f"api-{b['id']}",  # avoid conflicting with local bundle IDs
                "name": b["name"],
                "network": b["network"],
                "price": float(b["price"]),
                "is_api": True
            })

    except Exception:
        messages.error(request, "Failed to load API bundles.")
        api_bundles = []

    # ---- FETCH LOCAL DB BUNDLES ----
    local_bundles = []
    for b in Bundle.objects.filter(is_active=True):
        local_bundles.append({
            "id": f"local-{b.id}",
            "name": b.name,
            "network": b.network,
            "price": float(b.price),
            "is_api": False,
            "original_id": b.id
        })

    # MERGED
    bundles = api_bundles + local_bundles

    # ---- FORM SUBMISSION ----
    if request.method == "POST":
        selected_id = request.POST.get("bundle_id")
        quantity = int(request.POST.get("quantity"))

        # find bundle
        selected = next((x for x in bundles if str(x["id"]) == str(selected_id)), None)
        if not selected:
            messages.error(request, "Bundle not found.")
            return redirect("buy_bundle")

        total_price = selected["price"] * quantity

        if wallet_balance < total_price:
            messages.error(request, "Insufficient wallet balance.")
            return redirect("buy_bundle")

        # Deduct wallet
        user_profile.wallet -= total_price
        user_profile.save()

        # Record purchase
        Purchase.objects.create(
            user=request.user,
            bundle=None,
            recipient=request.user.username,
            amount=total_price,
            status="PAID",
            details=f"{quantity} × {selected['name']} ({selected['network']})"
        )

        messages.success(request, f"Successfully bought {quantity} × {selected['name']}")
        return redirect("buy_bundle")

    return render(request, "buy_bundle.html", {
        "wallet": wallet_balance,
        "bundles": bundles
    })


@login_required
def sell_bundle(request):
    user_profile = request.user.userprofile

    # Ensure user is an agent
    if not user_profile.is_agent:
        messages.error(request, "You need to become an agent first.")
        return redirect("/agent-dashboard/")

    # Fetch bundles from API
    headers = {"Authorization": f"Bearer {settings.DATA_API_KEY}"}
    try:
        response = requests.get(
            f"{settings.DATA_API_BASE_URL}bundles?user_id={settings.DATA_API_USER_ID}",
            headers=headers,
            timeout=10
        )
        response.raise_for_status()
        bundles_data = response.json().get("bundles", [])
    except requests.RequestException:
        messages.error(request, "Failed to fetch bundles. Try again later.")
        bundles_data = []

    if request.method == "POST":
        bundle_id = request.POST.get("bundle_id")
        quantity = int(request.POST.get("quantity", 1))
        customer_phone = request.POST.get("customer_phone")

        # Find bundle from API
        selected_bundle = next((b for b in bundles_data if str(b["id"]) == str(bundle_id)), None)
        if not selected_bundle:
            messages.error(request, "Selected bundle does not exist.")
            return redirect("/sell-bundle/")

        total_price = Decimal(selected_bundle["price"]) * quantity
        commission_rate = Decimal("0.05")  # 5% commission

        # Create Sale record
        Sale.objects.create(
            agent=request.user,
            bundle=None,
            price=total_price,
            quantity=quantity
        )

        # Update agent profile with commission
        agent_profile = user_profile.agent_profile
        commission = total_price * commission_rate
        agent_profile.commission_earned += commission
        agent_profile.total_sales += quantity
        agent_profile.total_sales_volume += total_price
        agent_profile.save()

        messages.success(
            request,
            f"Sold {quantity} × {selected_bundle['name']} to {customer_phone}. "
            f"Commission earned: GHS {commission:.2f}"
        )
        return redirect("/agent-dashboard/")

    return render(request, "sell_bundle.html", {"bundles": bundles_data})

@login_required
def withdraw_commission(request):
    # Ensure agent profile exists
    agent_profile, created = AgentProfile.objects.get_or_create(user=request.user)
    available_commission = agent_profile.commission_earned

    if request.method == "POST":
        try:
            amount = Decimal(request.POST.get("amount"))
            mobile_number = request.POST.get("mobile_number")

            if amount <= 0 or amount > available_commission:
                messages.error(request, "Invalid withdrawal amount.")
                return redirect("withdraw_commission")

            # ---------------------------
            # STEP 1: CREATE PAYSTACK RECIPIENT
            # ---------------------------
            headers = {
                "Authorization": f"Bearer {settings.PAYSTACK_SECRET_KEY}",
                "Content-Type": "application/json",
            }

            recipient_payload = {
                "type": "mobile_money",
                "name": request.user.username,
                "account_number": mobile_number,
                "currency": "GHS"
            }

            recipient_res = requests.post(
                "https://api.paystack.co/transferrecipient",
                json=recipient_payload,
                headers=headers
            ).json()

            if not recipient_res.get("status"):
                messages.error(request, f"Recipient creation failed: {recipient_res.get('message')}")
                return redirect("withdraw_commission")

            recipient_code = recipient_res["data"]["recipient_code"]

            # ---------------------------
            # STEP 2: SEND TRANSFER
            # ---------------------------
            transfer_payload = {
                "source": "balance",
                "amount": int(amount * 100),
                "recipient": recipient_code,
                "reason": "Agent Commission Withdrawal"
            }

            transfer_res = requests.post(
                "https://api.paystack.co/transfer",
                json=transfer_payload,
                headers=headers
            ).json()

            if transfer_res.get("status"):
                # Deduct commission
                agent_profile.commission_earned -= amount
                agent_profile.save()

                # Save withdrawal record
                Withdrawal.objects.create(
                    agent=request.user,
                    amount=amount,
                    mobile_number=mobile_number,
                    status="COMPLETED",
                    processed_at=timezone.now()
                )

                messages.success(request, f"Withdrawal of GHS {amount:.2f} sent to {mobile_number} successfully!")
            else:
                messages.error(request, f"Transfer failed: {transfer_res.get('message')}")

        except Exception as e:
            messages.error(request, f"Error: {str(e)}")

        return redirect("withdraw_commission")

    # GET request renders page
    return render(request, "withdraw_commission.html", {
        "available_commission": available_commission
    })
