from django.urls import path
from django.shortcuts import redirect
from core import views

urlpatterns = [
    path("", lambda request: redirect("login"), name="home"),
    
    path("login/", views.login_user, name="login"),
    path("signup/", views.signup_user, name="signup"),
    path("logout/", views.logout_user, name="logout"),

    # Agent
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

    # 🔥 CUSTOM SUPERADMIN DASHBOARD (no conflict)
    path("superadmin-dashboard/", views.admin_dashboard, name="admin_dashboard"),
    path("superadmin/add-bundle/", views.admin_add_bundle, name="admin_add_bundle"),
    path("superadmin/update-wallet/", views.admin_update_agent_wallet, name="admin_update_agent_wallet"),
    path("superadmin/set-registration-fee/", views.admin_set_registration_fee, name="admin_set_registration_fee"),
    path('superadmin/deduct-wallet/', views.admin_deduct_agent_wallet, name='admin_deduct_agent_wallet'),

    # NEW: Cards Pages
    path("superadmin/agents/", views.admin_agents_view, name="admin_agents"),
    path("superadmin/wallets/", views.admin_wallets_view, name="admin_wallets"),
    path("superadmin/orders-today/", views.admin_orders_today_view, name="admin_orders_today"),
    path("superadmin/agents/toggle/<int:agent_id>/", views.admin_toggle_agent, name="admin_toggle_agent")

]
