import re
import os
import time
import cv2
import base64
import requests
import sqlite3
import hashlib
import math
import stripe
from anthropic import Anthropic
from pydub import AudioSegment
from dotenv import load_dotenv
import stripe.error
from data_utils import get_db_connection, log_token_usage_and_cost
from data_utils_gpt4o import log_token_usage_and_cost_gpt4o
from basic_audio_utils import summarize_video_basic
from flask import Flask, request, render_template, redirect, url_for, flash, session, send_file, jsonify
from functools import wraps
from elevenlabs import save
from elevenlabs.client import ElevenLabs
from decorators import basic_required, premium_required
from stripe_utils import create_checkout_session_basic, create_checkout_session_premium, handle_stripe_webhook
from db_utils import init_db, update_db_schema, hash_REMOVED
from text_adjustment import adjust_text_for_duration
from audio_utils import generate_key_frame_phrases, extract_phrases, generate_audio_from_text, save_audio, analyze_frame, generate_sequential_summary, summarize_text, encode_image, extract_frames, calculate_frame_interval, save_audio
from tts_audio import generate_audio_with_openai
from tts_token_logging import log_tts_usage_and_cost, count_characters
from send_email import generate_otp, send_otp_email, store_otp, validate_otp, generate_REMOVED_reset_token, verify_REMOVED_reset_token, send_REMOVED_reset_email, send_email

load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY')   # Required for session management and flashing messages


# Initialize Stripe with your secret key
stripe.api_key = os.getenv('STRIPE_API_KEY')

# Define the path for saving the audio file
AUDIO_SAVE_PATH = 'static/audio_output.mp3'

# Initialization and Schema update
init_db()
# Update the db schema
update_db_schema()

def hash_REMOVED(REMOVED):
    return hashlib.sha256(REMOVED.encode()).hexdigest()

# Password check
def is_REMOVED_valid(REMOVED):
    # At least 8 characters, contains at least one uppercase letter, one lowercase letter, one number, and one special character
    REMOVED_regex = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
    return re.match(REMOVED_regex, REMOVED) is not None

def signup(username, REMOVED, first_name, last_name, dob, email):
    REMOVED_hash = hash_REMOVED(REMOVED)

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('''
                       INSERT INTO users (username, REMOVED_hash, first_name, last_name, dob, email, video_duration, subscription_status) 
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                       (username, REMOVED_hash, first_name, last_name, dob, email, 0.0, 'inactive')
                    )
        
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def login(username, REMOVED):
    REMOVED_hash = hash_REMOVED(REMOVED)
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ? AND REMOVED_hash = ?', (username, REMOVED_hash))
    user = cursor.fetchone()
    conn.close()
    return user is not None

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login_route'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def main_route():
    return render_template('main.html')

@app.route('/home')
@login_required
@premium_required
def home():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup_route():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        dob = request.form['dob']
        username = request.form['username']
        REMOVED = request.form['REMOVED']
        confirm_REMOVED = request.form['confirm_REMOVED']
        email = request.form['email']
        subscription_tier = request.form['subscription_tier']

        # Check if REMOVEDs match 
        if REMOVED != confirm_REMOVED:
            flash('Passwords do not match. Please try again.')
            return redirect('signup_route')
        
        # Validate REMOVED strength
        if not is_REMOVED_valid(REMOVED):
            flash('Password must be at least 8 characters long, contain both uppercase and lowercase letters, one number, and one special character.')
            return redirect(url_for('signup_route'))

        if signup(username, REMOVED, first_name, last_name, dob, email):
            session['username'] = username
            session['logged_in'] = True
            session['subscription_tier'] = subscription_tier  # Ensure tier is stored in session
            session['subscription_status'] = 'inactive'  # Set initial subscription status

            flash('Signup successful! Redirecting to payment...')

            # Create Stripe checkout session based on the subscription tier
            try:
                if subscription_tier == 'basic':
                    price_id = 'price_1PyQBqGWB2OjKBV44jdpOtqm'  # Replace with actual Basic Price ID
                elif subscription_tier == 'premium':
                    price_id = 'price_1PyQDpGWB2OjKBV4LL3FTYS2'  # Replace with actual Premium Price ID
                
                # Use price ID for the subscription tier
                checkout_session = stripe.checkout.Session.create(
                    payment_method_types=['card'],
                    line_items=[{
                        'price': price_id,
                        'quantity': 1,
                    }],
                    mode='subscription',
                    success_url=url_for('payment_successful', _external=True) + "?session_id={CHECKOUT_SESSION_ID}",
                    cancel_url=url_for('signup_route', _external=True),
                )
                return redirect(checkout_session.url, code=303)
            except Exception as e:
                return str(e)
        else:
            flash('Username already exists!')
    return render_template('signup.html', tier=request.args.get('tier'))


@app.route('/payment-successful')
@login_required
def payment_successful():
    # Retrieve session and Stripe subscription
    checkout_session = stripe.checkout.Session.retrieve(request.args.get('session_id'))

    # Get subscription ID and customer ID from Stripe
    subscription_id = checkout_session.subscription  # Get subscription ID from Stripe
    customer_id = checkout_session.customer  # Get customer ID


    # Update subscription status in the database
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE users
        SET subscription_status = 'active',
            subscription_id = ?, -- Store the Stripe subscription ID
            stripe_customer_id = ?, -- Store the Stripe customer ID
            tier = ?
        WHERE username = ?
    ''', (subscription_id, customer_id, session['subscription_tier'], session['username']))
    conn.commit()
    conn.close()

    # Update session status
    session['subscription_status'] = 'active'

    # Redirect user to the login page
    flash('Payment successful! Please log in to verify your email and continue.')
    return redirect(url_for('login_route'))

@app.route('/send-otp', methods=['POST'])
def send_otp_route():
    if 'username' not in session:
        return redirect(url_for('login_route'))
    
    username = session['username']
    # Fetch user's email based on the username (assuming user emails are stored)
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT email FROM users WHERE username = ?', (username,))
    user_data = cursor.fetchone()
    conn.close()

    if user_data:
        email = user_data[0]
        otp = generate_otp() # Generate OTP
        store_otp(email, otp) # Store the OTP
        send_otp_email(email, otp) # Send the OTP via email
        flash('OTP sent to your email address')
    else:
        flash('User not found')

    return render_template('otp_verification.html')  # Render OTP verification page

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp_route():
    print(session)
    if 'username' not in session:
        return redirect(url_for('login_route'))
    
    if request.method == 'POST':
        otp_entered = request.form['otp']
        username = session['username']

        # Fetch users email based on the username
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT email FROM users WHERE username = ?', (username,))
        user_data = cursor.fetchone()
        conn.close()

        if user_data:
            email = user_data[0]
            is_valid, message = validate_otp(email, otp_entered)
            if is_valid:
                flash('OTP verified successfully')

                # Fetch subscription status and tier after OTP verification
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute('SELECT subscription_status, tier FROM users WHERE username = ?', (username,))
                user_data =  cursor.fetchone()
                conn.close()

                if user_data:
                    subscription_status, tier = user_data
                    # Update the session with subscription details
                    session['subscription_status'] = subscription_status
                    session['subscription_tier'] = tier

                    # Redirect based on subscription status and tier
                    if subscription_status == 'active':
                        if tier == 'premium':
                            flash('Login successful! Welcome to your premium dashboard.')
                            return redirect(url_for('home'))
                        elif tier == 'basic':
                            flash('Login successful! Welcome to the TTS page.')
                            return redirect(url_for('text_to_speech'))
                    else:
                        flash('Your subscription is inactive. Please subscribe to continue.')
                        return redirect(url_for('subscribe_basic'))
                else:
                    flash('Error retrieving user data')
            else:
                flash(message)  # Display OTP error message (e.g., "OTP expired" or "Invalid OTP")
        else:
            flash('User not found')

    return render_template('otp_verification.html')

@app.route('/forgot-username', methods=['GET', 'POST'])
def forgot_username_route():
    if request.method == 'POST':
        email = request.form['email']

        # Check if email exists in the database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT username FROM users WHERE email = ?', (email,))
        result = cursor.fetchone()
        conn.close()

        if result:
            username = result[0]
            # Send an email with the username (implement the send_email function)
            send_email(email, 'Your Username', f'Your username is: {username}')
            flash('Your username has been sent to your email address.')
        else:
            flash('Email not found.')
        return redirect(url_for('forgot_username_route'))

    return render_template('forgot_username.html')

@app.route('/forgot-REMOVED', methods=['GET', 'POST'])
def forgot_REMOVED_route():
    if request.method == 'POST':
        email = request.form['email']

        # Check if email exists in the database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT username FROM users WHERE email = ?', (email,))
        result = cursor.fetchone()
        conn.close()

        if result:
            token = generate_REMOVED_reset_token(email)  # Generate a secure token
            reset_link = url_for('reset_REMOVED_route', token=token, _external=True)
            # Send the reset link via email (implement the send_email function)
            send_REMOVED_reset_email(email, f'Click the link to reset your REMOVED: {reset_link}')
            flash('Password reset instructions have been sent to your email.')
            print(f"Reset link: {reset_link}")
        else:
            flash('Email not found.')

        return redirect(url_for('forgot_REMOVED_route'))

    return render_template('forgot_REMOVED.html')

@app.route('/reset-REMOVED/<token>', methods=['GET', 'POST'])
def reset_REMOVED_route(token):
    # Verify the token and fetch the user's email
    email = verify_REMOVED_reset_token(token)

    if not email:
        flash('Invalid or expired token.')
        return redirect(url_for('forgot_REMOVED_route'))

    if request.method == 'POST':
        print(f"Received token: {token}")
        new_REMOVED = request.form['REMOVED']
        confirm_REMOVED = request.form['confirm_REMOVED']

        if new_REMOVED != confirm_REMOVED:
            flash('Passwords do not match.')
            print('Pasword doesnt match')
            return redirect(url_for('reset_REMOVED_route', token=token))

        # Hash the new REMOVED and update the database
        REMOVED_hash = hash_REMOVED(new_REMOVED)
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET REMOVED_hash = ? WHERE email = ?', (REMOVED_hash, email))
        conn.commit()
        conn.close()

        flash('Your REMOVED has been updated successfully.')
        return redirect(url_for('login_route'))

    return render_template('reset_REMOVED.html', token=token)

@app.route('/login', methods=['GET', 'POST'])
def login_route():
    if request.method == 'POST':
        username = request.form['username']
        REMOVED = request.form['REMOVED']
        if login(username, REMOVED):
            # Fetch user subscription details
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT email FROM users WHERE username = ?', (username,))
            user_data = cursor.fetchone()
            conn.close()

            if user_data:
                email = user_data[0]
                otp = generate_otp() # Generate OTP
                store_otp(email, otp) # Store OTP in temporary storage
                send_otp_email(email, otp) # Send OTP to user's email

                session['username'] = username
                session['logged_in'] = True
                session['otp_sent'] = True
                print(username)

                flash('OTP sent to your email address for verification')
                return redirect(url_for('verify_otp_route')) # Redirect to OTP verification page
            else:
                flash('Email not found for the user.')
        else:
            flash('Invalid username or REMOVED')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)  # Remove logged_in from session
    flash('You have been logged out.')
    return redirect(url_for('login_route'))

# How to prompt route
@app.route('/how-to-prompt')
def how_to_prompt():
    return render_template('prompt.html')

# Basic page
@app.route('/basic')
def basic():
    return render_template('basic.html')

#Premium route
@app.route('/premium')
def premium():
    return render_template('premium.html')

# Pricing page route
@app.route('/pricing')
def pricing():
    return render_template('pricing.html')

# Contact page route
@app.route('/contact')
def contact():
    return render_template('contact.html')

# Account page route
@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    # Get the username from the account session
    username = session.get('username')

    if request.method == 'POST':
        # Handle subscription change form submission
        new_tier = request.form['subscription_tier']

        # Fetch current subscription details from the database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT subscription_id, tier FROM users WHERE username = ?', (username,))
        result = cursor.fetchone()
        subscription_id, current_tier = result if result else (None, None)
        conn.close()
        print(f"Subscription ID: {subscription_id}")

        # If the new tier is the same as the current tier, notify the user
        if new_tier == current_tier:
            flash('You are already on this subscription tier.')
            return redirect(url_for('account'))
        
        # Update the existing Stripe subscription with the new price ID
        try:
            if new_tier == 'basic':
                price_id = 'price_1PyQBqGWB2OjKBV44jdpOtqm'
            elif new_tier == 'premium':
                price_id = 'price_1PyQDpGWB2OjKBV4LL3FTYS2'

            # Retrieve the subscription object from Stripe
            subscription = stripe.Subscription.retrieve(subscription_id)
            
            # Get the subscription item ID (the specific plan within the subscription)
            subscription_item_id = subscription['items']['data'][0].id
            
            # Modify the subscription with the new price ID
            stripe.Subscription.modify(
                subscription_id,
                items=[{
                    'id': subscription_item_id,  # Use the correct subscription item ID
                    'price': price_id  # The new price ID to update the subscription
                }]
            )
            print("Stripe subscription updated successfully.")
            # Update the subscription tier and reset the video duration in the database
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE users
                SET tier = ?, 
                    video_duration = 0  -- Reset video duration
                WHERE username = ?
            ''', (new_tier, username))
            conn.commit()
            conn.close()

            session['subscription_tier'] = new_tier # Update session with the new tier
            flash('Your subscription has been successfully updated!')
            return redirect(url_for('account'))
        except Exception as e:
            print(f"Error updating Stripe subscription: {str(e)}")
            flash(f'Error updating subscription: {str(e)}')
            return redirect(url_for('account'))
    
    # For GET request, fetch the user data and render the account page
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT first_name, last_name, username, email, tier, video_duration FROM users WHERE username = ?', (username,))
    user_data = cursor.fetchone()
    conn.close()

    if user_data:
        first_name, last_name, username, email, subscription_tier, video_duration = user_data
        # Convert video_duration from seconds to minutes (round to nearest minute)
        video_duration_minutes = round(video_duration / 60, 2)
        return render_template('accounts.html', first_name=first_name, last_name=last_name, username=username, email=email, subscription_tier=subscription_tier, video_duration_minutes=video_duration_minutes)
    else:
        flash('User not found')
        return redirect(url_for('login_route'))


@app.route('/change_REMOVED', methods=['GET', 'POST'])
@login_required
def change_REMOVED():
    username = session.get('username')
    
    if not username:
        flash("You need to be logged in to change your REMOVED.")
        return redirect(url_for('login_route'))

    if request.method == 'POST':
        current_REMOVED = request.form['current_REMOVED']
        new_REMOVED = request.form['new_REMOVED']
        confirm_new_REMOVED = request.form['confirm_new_REMOVED']

        # Verify current REMOVED
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT REMOVED_hash FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()

        # Since fetchone() returns a tuple, access the REMOVED_hash using index 0
        if not user or user[0] != hash_REMOVED(current_REMOVED):
            flash('Current REMOVED is incorrect.')
            return redirect(url_for('change_REMOVED'))

        # Check if new REMOVEDs match
        if new_REMOVED != confirm_new_REMOVED:
            flash('New REMOVEDs do not match.')
            return redirect(url_for('change_REMOVED'))

        # Validate the new REMOVED strength
        if not is_REMOVED_valid(new_REMOVED):
            flash('Password must be at least 8 characters long, contain uppercase, lowercase letters, a number, and a special character.')
            return redirect(url_for('change_REMOVED'))

        # Update the REMOVED in the database
        new_REMOVED_hash = hash_REMOVED(new_REMOVED)
        cursor.execute('UPDATE users SET REMOVED_hash = ? WHERE username = ?', (new_REMOVED_hash, username))
        conn.commit()
        conn.close()

        flash('Password successfully updated.')
        return redirect(url_for('account'))

    return render_template('change_REMOVED.html')

# Update card payment
@app.route('/update_payment', methods=['POST'])
@login_required
def update_payment():
    # Get the current user's stripe_customer_id from your database
    username = session.get('username')

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT stripe_customer_id FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()
    stripe_customer_id = result[0] if result else None
    conn.close()

    if stripe_customer_id:
        try:
            # Rename the Stripe session variable to avoid conflict with Flask's session
            stripe_session = stripe.billing_portal.Session.create(
                customer=stripe_customer_id,
                return_url=url_for('account', _external=True)  # Redirect to the account page after update
            )

            # Redirect the user to Stripe's customer portal
            return redirect(stripe_session.url)
        except Exception as e:
            flash(f'Error creating Stripe customer portal session: {str(e)}')
            return redirect(url_for('account'))
    else:
        flash('Stripe customer ID not found. Please contact support.')
        return redirect(url_for('account'))

# Unsubscribe route
@app.route('/unsubscribe', methods=['POST'])
@login_required
def unsubscribe():
    # Get the username from the session
    username = session.get('username')

    if not username:
        flash('You are not logged in')
        return redirect(url_for('login_route'))
    
    # Fetch the user's Stripe subscription ID from the database
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT subscription_id FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()
    subscription_id = result[0] if result else None
    conn.close()

    if subscription_id:
        try:
            # Cancel the Stripe subscription
            stripe.Subscription.delete(subscription_id)
        except Exception as e:
            flash(f'Error cancelling subscription in Stripe: {str(e)}')
            return redirect(url_for('account'))
        
        # Update subscription status in the database to 'inactive'
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE users
            SET subscription_status = 'inactive'
            WHERE username = ?
        ''', (username,))
        conn.commit()
        conn.close()

        # Update the session status
        session['subscription_status'] = 'inactive'

        # Notify the user
        flash('You have successfully unsubscribed')
    else:
        flash('Subscription not found')

    return redirect(url_for('account'))

# Subscription routes
@app.route('/subscribe-basic')
@login_required
def subscribe_basic():
    return render_template('subscribe_basic.html')

@app.route('/subscribe-premium')
@login_required
def subscribe_premium():
    return render_template('subscribe_premium.html')

def handle_stripe_webhook(payload, sig_header, webhook_secret):
    try:
        # Verify the strip webhook signature using Stripe's library
        event = stripe.Webhook.construct_event(
            payload, sig_header, webhook_secret
        )
    except ValueError as e:
        #  Invalid payload
        return jsonify({'status': 'invalid payload'}), 400
    except stripe.error.SignatureVerificationError as e:
        # Invalid Signature
        return jsonify({'status': 'invalid signature'}), 400
    
    # Process the event from stripe
    if event['type'] == 'invoice.payment_succeeded':
        invoice = event['data']['object']
        customer_id = invoice['customer']

        # Use customer_id to fetch customer data from Stripe if needed
        stripe_customer = stripe.Customer.retrieve(customer_id)
        customer_email = stripe_customer['email']

        # Update the users subscription status in the database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE users
            SET video_duration = 0, -- Reset video_duration
                subscription_status = 'active'  -- Reactivate the user for the new period
            WHERE email = ?
        ''', (customer_email,))
        conn.commit()
        conn.close()

        return jsonify({'status': 'success'}), 200
    
    elif event['type'] == 'invoice.created':
        # Handle invoice.created event
        print("Invoice created:", event['data']['object']['id'])
        return jsonify({'status': 'invoice created processed'}), 200
    
    elif event['type'] == 'invoice.updated':
        # Handle invoice.updated event
        print("Invoice updated:", event['data']['object']['id'])
        return jsonify({'status': 'invoice updated processed'}), 200
    
    elif event['type'] == 'invoice.finalized':
        # Handle invoice.finalized event
        print("Invoice finalized:", event['data']['object']['id'])
        return jsonify({'status': 'invoice finalized processed'}), 200
    
    elif event['type'] == 'invoice.paid':
        # Handle paid invoices
        print("Invoice paid:", event['data']['object']['id'])
        return jsonify({'status': 'invoice paid processed'})
    
    elif event['type'] == 'customer.subscription.deleted':
        # Handle subscription cancellation from Stripe
        subscription = event['data']['object']
        customer_id = subscription['customer']

        # Get the email from Stripe customer data
        stripe_customer = stripe.Customer.retrieve(customer_id)
        customer_email = stripe_customer['email']

        # Update the user's subscription status in the database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE users
            SET subscription_status = 'inactive'
            WHERE email = ?
        ''', (customer_email,))
        conn.commit()
        conn.close()

        return jsonify({'status': 'subscription canceled successfully'}), 200
    
    
    # Handle other event types here if needed
    else:
        # Event type is not explicitly handled, but respond with 200
        print(f"Unhandled event type: {event['type']}")
        return jsonify({'status': 'event not processed'}), 400
    
@app.route('/create-checkout-session-basic', methods=['POST'])
@login_required
def create_checkout_session_basic_route():
    return create_checkout_session_basic()

@app.route('/create-checkout-session-premium', methods=['POST'])
@login_required
def create_checkout_session_premium_route():
    return create_checkout_session_premium()

@app.route('/stripe-webhook', methods=['POST'])
def stripe_webhook_route():
    print("Webhook received")
    payload = request.get_data(as_text=True)
    sig_header = request.headers.get('Stripe-Signature')
    webhook_secret = os.getenv('STRIPE_WEBHOOK_SECRET')
    
    # Call the handle_stripe_webhook function to process the event
    return handle_stripe_webhook(payload, sig_header, webhook_secret)

# --- Video Processing Logic ---
ELEVENLABS_API_KEY = os.getenv('ELEVENLABS_API_KEY')


def summarize_video(video_path, frame_interval, max_frame_for_last_key, api_key, custom_prompt, custom_prompt_frame, username):
    print("Starting video summarization process...")
    frames = extract_frames(video_path, frame_interval)
    summaries = []
    
    # Calculate the video duration
    vidcap = cv2.VideoCapture(video_path)
    fps = vidcap.get(cv2.CAP_PROP_FPS)
    frame_count = int(vidcap.get(cv2.CAP_PROP_FRAME_COUNT))
    video_duration = frame_count / fps
    vidcap.release()

    # Debugging: Print video duration to verify it's calculated correctly
    print(f"Calculated video duration: {video_duration} seconds")

    words_per_minute = 145
    total_words = math.ceil((video_duration / 60) * words_per_minute)
    print(f'Calculated target word count based on video duration: {total_words} words')

    if video_duration > 120:
        buffer_percentage = 0.1
        total_words += math.ceil(total_words * buffer_percentage)
        print(f"Added buffer: New total characters = {total_words}")

    key_frame_times = []
    for i, frame in enumerate(frames):
        # Adjust frame calculation based on actual frame extraction
        frame_time = ((i + 1) * frame_interval) / fps # Calculate the time of the current frame
        if frame_time * fps > max_frame_for_last_key: # Stop if the frame is beyond the allowed max frame
            break
        key_frame_times.append(frame_time)

        print(f"Analyzing frame {i+1}/{len(frames)} at time {frame_time:.2f} seconds")
        encoded_frame = encode_image(frame)
        analysis_result = analyze_frame(encoded_frame, api_key, username)

        if "Error" in analysis_result:
            print(f"Frame {i+1} analysis failed: {analysis_result}")
        else:
            frame_label = f"Frame {i+1}:"
            frame_summary = f"{frame_label} {analysis_result}"
            print(f"{frame_label} summary: {frame_summary}")
            summaries.append(frame_summary)

    combined_summary = " ".join(summaries)
    print(f"Combined summary of key frames: {combined_summary}")

    # Step 1: Create a quick sequential summary of the combined summary
    sequential_summary = generate_sequential_summary(combined_summary, api_key, username)

    # Step 2: Generate key frame phrases
    response_text = generate_key_frame_phrases(combined_summary, custom_prompt, api_key, username)
    frame_phrases = extract_phrases(response_text)

    # Debugging: Print the extracted key frame phrases and their indices
    print(f"Extracted key frame phrases: {frame_phrases}")
    print(f"Key frame times: {key_frame_times}")

    if len(frame_phrases) == 2:
        key_frame_one_time = key_frame_times[list(frame_phrases.keys())[0] - 1]
        key_frame_two_time = key_frame_times[list(frame_phrases.keys())[1] - 1]

        key_frame_one = list(frame_phrases.values())[0]
        key_frame_two = list(frame_phrases.values())[1]

        # Debugging: Print time of each key frame and corrisponding phrase
        print(f"Key frame 1 Time: {key_frame_one_time}, Phrase: {key_frame_one}")
        print(f"Key frame 2 Time: {key_frame_two_time}, Phrase: {key_frame_two}")

        # Generate final, short summary using key frame phrases
        final_summary = summarize_text(sequential_summary, total_words, api_key, username, custom_prompt, custom_prompt_frame, key_frame_one, key_frame_two, key_frame_one_time, key_frame_two_time, video_duration)

        # **Debugging: Print Original and Adjusted Summaries**
        print(f"Original summary: {final_summary}") 
        # Adjust the final summary to match the target duration before generating audio
        adjusted_summary = adjust_text_for_duration(final_summary, video_duration)
        print(f"Adjusted summary: {adjusted_summary}")

        print("Final summary generated:", final_summary)
        print("Video summarization complete.")

        return adjusted_summary
    else:
        return "Error: Could not generate key frame phrases"


@app.route('/upload', methods=['GET', 'POST'])
@login_required
@basic_required
@premium_required
def upload_video():
    # Debugging print to check received data
    print(request.form)
    custom_prompt = request.form.get('custom_prompt', '')
    custom_prompt_frame = request.form.get('custom_prompt_frame', '') # Get the custom frame prompt

    if custom_prompt == '':
        print("Custom prompt is empty")
    else:
        print(f"Received custom prompt: {custom_prompt}")
    if custom_prompt_frame == '':
        print("Custom prompt is empty.")
    else:
        print(f"Received custom frame prompt: {custom_prompt_frame}")

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT video_duration, subscription_status FROM users WHERE username = ?', (session['username'],))
    user = cursor.fetchone()

    video_duration = user[0]
    subscription_status = user[1]

    # Check if the user has exceeded 
    if video_duration >= 1800: # 1800 seconds = 30 minutes
        cursor.execute('''
            UPDATE users
            SET subscription_status = 'inactive'
            WHERE username = ?''', (session['username'],))
        conn.commit()
        conn.close()

        session['subscription_status'] = 'inactive'
        flash('You have reached your 30 minute limit. Please renew your subscription')
        return redirect(url_for('subscribe_premium'))
        

    admin_username = 'justinsamuelson7@gmail.com'
    if session['username'] == admin_username:
        flash('Admin privileges: No video processing limit applies to you.')
    else:
        if subscription_status != 'active':
            flash('You need to subscribe to process the videos.')
            return redirect(url_for('subscribe'))

    if 'file' not in request.files:
        return "No file part"
    file = request.files['file']
    if file.filename == '':
        return "No selected file"
    if file:
        video_path = os.path.join('uploads', file.filename)
        file.save(video_path)

        custom_prompt = request.form.get('custom_prompt', '')

        vidcap = cv2.VideoCapture(video_path)
        fps = vidcap.get(cv2.CAP_PROP_FPS)
        frame_count = int(vidcap.get(cv2.CAP_PROP_FRAME_COUNT))
        if fps == 0 or frame_count == 0:
            print(f"Error: Invalid video file or could not determine FPS/frame count. FPS: {fps}, Frame Count: {frame_count}")
            return "Error: Invalid video file or could not determine FPS/frame count"

        video_duration_increment = frame_count / fps
        vidcap.release() 

        # Update the users total video duration in the database
        new_total_video_duration = video_duration + video_duration_increment
        cursor.execute('''
            UPDATE users
            SET video_duration = ?
            WHERE username = ?''', (new_total_video_duration, session['username']))
        conn.commit()

        # Determine the number of key frames to extract based on video duration
        num_key_frames = 4 if video_duration_increment > 45 else 3 if video_duration_increment > 30 else 2
        frame_interval, max_frame_for_last_key = calculate_frame_interval(video_duration_increment, fps, num_key_frames)

        api_key = os.getenv("GPT_API_KEY")
        if not api_key:
            return "API key is not set. Please set the ELEVENLABS_API_KEY."
        
        # Generate the adjusted summary
        adjusted_summary = summarize_video(video_path, frame_interval, max_frame_for_last_key, api_key, custom_prompt, custom_prompt_frame, session['username'])

        # Check for errors before proceeding to audio generation
        if 'Error' not in adjusted_summary:
            # Generate audio from the summary
            voice_id = 'pNInz6obpgDQGcFmaJgB'
            audio = generate_audio_from_text(adjusted_summary, voice_id)
            output_filename = os.path.join('static', 'video_summary_audio.mp3')
            save_audio(audio, output_filename)
            return send_file(output_filename, as_attachment=True, download_name='video_summary_audio.mp3')
        else:
            # Handle the error properly, return to user or log it
            print(f"Error during summarization: {adjusted_summary}")
            flash("Error occurred during summarization. Please try again.")
            return redirect(url_for('upload_video'))  # Adjust as needed for your UI flow

@app.route('/tts', methods=['GET', 'POST'])
@login_required
@basic_required
def text_to_speech():
    if request.method == 'POST':
        # Retrieve prompt and video details from the form
        user_prompt = request.form.get('custom_prompt')
        if not user_prompt:
            flash('Please enter some text to generate speech')
            return render_template('tts.html')

        # Handle file upload and processing
        if 'file' not in request.files or request.files['file'].filename == '':
            flash('No selected or no file part in the request.')
            return render_template('tts.html')

        file = request.files['file']
        video_path = os.path.join('uploads', file.filename)
        file.save(video_path)

        # Capture video properties for duration
        vidcap = cv2.VideoCapture(video_path)
        fps = vidcap.get(cv2.CAP_PROP_FPS)
        frame_count = int(vidcap.get(cv2.CAP_PROP_FRAME_COUNT))
        video_duration = frame_count / fps
        vidcap.release()

        if fps == 0 or frame_count == 0:
            flash('Error: Invalid video file or could not determine FPS/frame count.')
            return render_template('tts.html')

        print(f"Video duration: {video_duration} seconds")

        # Set API key and other settings for analysis
        api_key = os.getenv("GPT_API_KEY")
        if not api_key:
            flash("API key is not set. Please set the API key in the environment.")
            return render_template('tts.html')
        
        # Get the username from the session
        username = session.get('username')
        if not username:
            flash("You need to be logged in to process videos.")
            return redirect(url_for('login'))
        
        # Connect to the database to retrieve the users current video duration
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('SELECT video_duration, subscription_status FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()

        if user is None:
            flash("User not found in database.")
            return redirect(url_for('login'))
        
        current_video_duration = user[0]
        subscription_status = user[1]


        # Check if the user's subscription is active
        if subscription_status == 'inactive':
            flash('Your subscription is inactive. Please renew your subscription to continue.')
            return redirect(url_for('subscribe_basic'))
        
        # Check if the user has exceeded the 10-minute limit for basic users
        total_video_duration = current_video_duration + video_duration
        if total_video_duration > 600:
            cursor.execute('''
                UPDATE users
                SET subscription_status = 'inactive'
                WHERE username = ?''', (username,))
            conn.commit()
            conn.close()      
            
            # Update session subscription status
            session['subscription_status'] = 'inactive'
            flash('You have reached your 10-minute limit. Upgrade to Premium for more video processing.')
            return redirect(url_for('subscribe'))
        
        # Update the user's video duration in the database
        cursor.execute('''
            UPDATE users
            SET video_duration = ?
            WHERE username = ?
        ''', (total_video_duration, username))
        conn.commit()
        conn.close()

        # Call the basic summarization function
        try:
            final_summary = summarize_video_basic(video_path, api_key, username, custom_prompt=user_prompt)
            print(f"Final summary: {final_summary}")

            # Adjust the summary to match the desired video duration
            adjusted_summary = adjust_text_for_duration(final_summary, video_duration)
            print(f"Adjusted Summary: {adjusted_summary}")

            # Check for errors before proceeding to audio generation
            if 'Error' not in final_summary:
                # Generate audio from the summary using your existing function
                audio_file_path = generate_audio_with_openai(adjusted_summary)

                # Count characters in final summary
                character_count = count_characters(final_summary)

                # Log the character usage and cost
                log_tts_usage_and_cost(username, character_count)

                # Serve the audio file to the user
                return send_file(audio_file_path, as_attachment=True, download_name='video_summary_audio.mp3')
            else:
                flash("Error occurred during summarization. Please try again.")
                return render_template('tts.html')

        except Exception as e:
            flash(f"Error during video summarization: {str(e)}")
            return render_template('tts.html')

    return render_template('tts.html')
    

    

if __name__ == "__main__":
    app.run(host='0.0.0.0')

