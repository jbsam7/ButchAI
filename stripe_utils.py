import stripe
import os
from flask import url_for, session, redirect
from data_utils import get_db_connection
from logger import logger

# Initialize Stripe with your secret key
stripe.api_key = os.getenv('STRIPE_API_KEY')

def create_checkout_session_basic():
    try:
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'usd',
                    'product_data': {
                        'name': 'Basic Narration Subscription',
                    },
                    'unit_amount': 500,  # Amount in cents ($5)
                    'recurring': {
                        'interval': 'month',
                    },
                },
                'quantity': 1,
            }],
            mode='subscription',
            client_reference_id=session['username'], # Pass the username as client_reference_id
            success_url=url_for('text_to_speech', _external=True),
            cancel_url=url_for('subscribe_basic', _external=True),
        )
        return redirect(checkout_session.url, code=303)
    except Exception as e:
        return str(e)

def create_checkout_session_premium():
    try:
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'usd',
                    'product_data': {
                        'name': 'Premium Narration Subscription',
                    },
                    'unit_amount': 1500,  # Amount in cents ($15)
                    'recurring': {
                        'interval': 'month',
                    },
                },
                'quantity': 1,
            }],
            mode='subscription',
            client_reference_id=session['username'], # Pass the username as client_reference_id
            success_url=url_for('home', _external=True),
            cancel_url=url_for('subscribe_premium', _external=True),
        )
        return redirect(checkout_session.url, code=303)
    except Exception as e:
        return str(e)

def handle_stripe_webhook(payload, sig_header, webhook_secret):
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, webhook_secret)
    except ValueError:
        return "Invalid payload", 400
    except stripe.error.SignatureVerificationError:
        return "Invalid signature", 400

    # Handle the checkout session completion
    if event['type'] == 'checkout.session.completed':
        session_data = event['data']['object']
        username = session_data.get('client_reference_id')
        subscription_id = session_data.get('subscription') # Get the subsription ID

        # Update the user's subscription status based on the session ID
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''UPDATE users
                          SET subscription_status = 'active',
                              tier = ?, 
                              stripe_subscription_id = ?                   
                          WHERE username = ?''', (session['tier'], subscription_id, username))
        conn.commit()
        conn.close()

    # Handle subscription renewal and reset video_duration
    elif event['type'] == 'invoice.payment_succeeded':
        invoice_data = event['data']['object']
        subscription_id = invoice_data.get['subscription']

        # Fetch the username based on the subscription ID 
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT username FROM users WHERE stripe_subscription_id = ?', (subscription_id,))
        user = cursor.fetchone()

        if user:
            username = user[0]

            # Reset the video duration for the user
            cursor.execute('''UPDATE users 
                              SET video_duration = 0.0
                              WHERE username = ?''', (username,))
            conn.commit()
        conn.close()

    return "Success", 200
