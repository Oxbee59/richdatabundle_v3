from django.urls import path
from django.shortcuts import redirect
from core import views

urlpatterns = [
    path("", lambda request: redirect("login"), name="home"),

    # Authentication
    path("login/", views.login_user, name="login"),
    path("signup/", views.signup_user, name="signup"),
    path("logout/", views.logout_user, name="logout"),

    # Agent
    path("agent-dashboard/", views.agent_dashboard, name="agent_dashboard"),
    path("buy-bundle/", views.buy_bundle, name="buy_bundle"),
    path("purchases/", views.purchases, name="purchases"),
    path("profile/", views.profile, name="profile"),
    
    path("api-docs/", views.api_docs, name="api_docs"),
    path("api-docs/generate-keys/", views.generate_api_keys, name="generate_api_keys"),

    path("load-wallet/", views.load_wallet, name="load_wallet"),
    path("wallet/callback/", views.wallet_callback, name="wallet_callback"),
    path("paystack/webhook/", views.paystack_webhook, name="paystack_webhook"),
    path("become-agent/", views.become_agent, name="become_agent"),
    path("sell-bundle/", views.sell_bundle, name="sell_bundle"),
    path("contact-admin/", views.contact_admin, name="contact_admin"),

    # Superadmin / Admin
    path("superadmin-dashboard/", views.admin_dashboard, name="admin_dashboard"),
    path("superadmin/add-bundle/", views.admin_add_bundle, name="admin_add_bundle"),
    path("superadmin/update-wallet/", views.admin_update_agent_wallet, name="admin_update_agent_wallet"),
    path("superadmin/set-registration-fee/", views.admin_set_registration_fee, name="admin_set_registration_fee"),
    path("superadmin/deduct-wallet/", views.admin_deduct_agent_wallet, name="admin_deduct_agent_wallet"),

    # Cards / Admin Views
    path("superadmin/wallets/", views.admin_wallets, name="admin_wallets"),
    path("superadmin/orders-today/", views.admin_orders, name="admin_orders"),

    # Admin Agents
    path('superadmin/agents/', views.admin_agents, name='admin_agents'),
    path('superadmin/agents/make-staff/<int:user_id>/', views.admin_make_staff, name='admin_make_staff'),
    path('superadmin/agents/delete/<int:user_id>/', views.admin_delete_agent, name='admin_delete_agent'),

    # Bundle Editing & Deleting
    path("superadmin/bundles/edit/<int:bundle_id>/", views.admin_edit_bundle, name="admin_edit_bundle"),
    path("superadmin/bundles/delete/<int:bundle_id>/", views.admin_delete_bundle, name="admin_delete_bundle"),

    # Messages
    path("superadmin/messages/delete/<int:message_id>/", views.admin_delete_message, name="admin_delete_message"),
]
