from django.urls import path
from django.shortcuts import redirect
from core import views

urlpatterns = [
    path("", lambda request: redirect("login"), name="home"),
    path("login/", views.login_user, name="login"),
    path("signup/", views.signup_user, name="signup"),
    path("logout/", views.logout_user, name="logout"),
    path("agent-dashboard/", views.agent_dashboard, name="agent_dashboard"),
    path("buy-bundle/", views.buy_bundle, name="buy_bundle"),
    path("purchases/", views.purchases, name="purchases"),
    path("profile/", views.profile, name="profile"),
    path("api-docs/", views.api_docs, name="api_docs"),
    path("load-wallet/", views.load_wallet, name="load_wallet"),
    path("wallet/callback/", views.wallet_callback, name="wallet_callback"),
    path("paystack/webhook/", views.paystack_webhook, name="paystack_webhook"),
    path("become-agent/", views.become_agent, name="become_agent"),
    path("sell-bundle/", views.sell_bundle, name="sell_bundle"),
    path("contact-admin/", views.contact_admin, name="contact_admin"),

    # admin functions
    path("admin-dashboard/", views.admin_dashboard, name="admin_dashboard"),
    path("admin/add-bundle/", views.admin_add_bundle, name="admin_add_bundle"),
    path("admin/update-wallet/", views.admin_update_agent_wallet, name="admin_update_agent_wallet"),
    path("admin/set-registration-fee/", views.admin_set_registration_fee, name="admin_set_registration_fee"),

]
