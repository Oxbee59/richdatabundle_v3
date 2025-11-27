import requests
from django.conf import settings

PAYSTACK_SECRET_KEY = settings.PAYSTACK_SECRET_KEY

def paystack_initialize(email, amount, reference, callback_url):
    url = "https://api.paystack.co/transaction/initialize"
    headers = {"Authorization": f"Bearer {PAYSTACK_SECRET_KEY}"}

    payload = {
        "email": email,
        "amount": int(amount * 100),
        "reference": reference,
        "callback_url": callback_url
    }

    response = requests.post(url, json=payload, headers=headers)
    return response.json()
