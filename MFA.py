import streamlit as st
import numpy as np
import pyotp
import random
import string
from captcha.image import ImageCaptcha
import yaml
from yaml.loader import SafeLoader
import os
import time
from PIL import Image
import io
import base64
import hashlib
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Set page configuration
st.set_page_config(
    page_title="Multi-Factor Authentication System",
    page_icon="🔐",
    layout="wide"
)

# Initialize session states
if 'authenticated' not in st.session_state:
    st.session_state['authenticated'] = False
if 'current_step' not in st.session_state:
    st.session_state['current_step'] = 'login'
if 'captcha_verified' not in st.session_state:
    st.session_state['captcha_verified'] = False
if 'otp_verified' not in st.session_state:
    st.session_state['otp_verified'] = False
if 'fingerprint_verified' not in st.session_state:
    st.session_state['fingerprint_verified'] = False
if 'username' not in st.session_state:
    st.session_state['username'] = None
if 'name' not in st.session_state:
    st.session_state['name'] = None

# Create necessary directories if they don't exist
os.makedirs('fingerprints', exist_ok=True)
os.makedirs('data', exist_ok=True)

# User database file
USER_DB_FILE = 'data/users.yaml'

# Load or create user database
def load_users():
    try:
        with open(USER_DB_FILE) as file:
            users = yaml.load(file, Loader=SafeLoader)
            return users or {}
    except FileNotFoundError:
        return {}

# Save user database
def save_users(users):
    with open(USER_DB_FILE, 'w') as file:
        yaml.dump(users, file, default_flow_style=False)

# Hash password
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Verify password
def verify_password(stored_hash, provided_password):
    return stored_hash == hash_password(provided_password)

# Generate OTP
def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

# Send OTP via email (simulated)
def send_otp(email, otp):
    # In a real application, you would configure this with your SMTP server
    # For this example, we'll just simulate sending an email
    st.info(f"Simulating email to {email} with OTP: {otp}")
    
    # Uncomment and configure this section to actually send emails
    """
    sender_email = "your_email@gmail.com"
    sender_password = "your_app_password"  # Use app password for Gmail
    
    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = email
    message["Subject"] = "Your OTP for Authentication"
    
    body = f"Your one-time password is: {otp}\nThis code will expire in 5 minutes."
    message.attach(MIMEText(body, "plain"))
    
    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, email, message.as_string())
        server.quit()
        return True
    except Exception as e:
        st.error(f"Failed to send email: {e}")
        return False
    """
    return True

# CAPTCHA generation function
def generate_captcha(length=6, width=200, height=100):
    captcha_text = ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))
    image = ImageCaptcha(width=width, height=height)
    data = image.generate(captcha_text)
    return captcha_text, data

# Fingerprint verification function
def verify_fingerprint():
    st.subheader("Fingerprint Authentication")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.info("Place your finger on the fingerprint sensor")
        
        # Simulate fingerprint sensor reading
        if st.button("Scan Fingerprint"):
            with st.spinner("Reading fingerprint..."):
                # In a real application, you would interface with the device's fingerprint sensor here
                # For simulation, we'll just wait and then succeed
                time.sleep(2)
                
                # Simulate successful fingerprint match
                st.success("Fingerprint verified successfully!")
                st.session_state['fingerprint_verified'] = True
                time.sleep(1)
                st.rerun()
    
    with col2:
        st.image("https://www.bioenabletech.com/wp-content/uploads/2018/07/Fingerprint-Identification.jpg", 
                 caption="Fingerprint Scanning", width=300)

# OTP verification function
def verify_otp():
    st.subheader("OTP Verification")
    
    users = load_users()
    username = st.session_state.get('username', '')
    
    if username and username in users:
        user_data = users[username]
        email = user_data.get('email', 'user@example.com')
        
        col1, col2 = st.columns(2)
        
        with col1:
            if 'otp' not in st.session_state:
                # Generate and send OTP
                otp = generate_otp()
                st.session_state['otp'] = otp
                st.session_state['otp_time'] = time.time()
                
                if send_otp(email, otp):
                    st.info(f"OTP has been sent to {email}")
                else:
                    st.error("Failed to send OTP. Please try again.")
            
            # Display time remaining for OTP validity (5 minutes)
            if 'otp_time' in st.session_state:
                elapsed = time.time() - st.session_state['otp_time']
                remaining = max(0, 300 - elapsed)  # 5 minutes = 300 seconds
                
                if remaining > 0:
                    st.write(f"OTP expires in: {int(remaining // 60)}:{int(remaining % 60):02d}")
                else:
                    st.warning("OTP has expired. Please request a new one.")
                    if st.button("Request New OTP"):
                        if 'otp' in st.session_state:
                            del st.session_state['otp']
                        if 'otp_time' in st.session_state:
                            del st.session_state['otp_time']
                        st.rerun()
        
        with col2:
            otp_input = st.text_input("Enter the 6-digit OTP sent to your email", max_chars=6)
            
            if st.button("Verify OTP"):
                if 'otp' in st.session_state:
                    if time.time() - st.session_state['otp_time'] <= 300:  # 5 minutes validity
                        if otp_input == st.session_state['otp']:
                            st.success("OTP verified successfully!")
                            st.session_state['otp_verified'] = True
                            time.sleep(1)
                            st.rerun()
                        else:
                            st.error("Invalid OTP. Please try again.")
                    else:
                        st.error("OTP has expired. Please request a new one.")
                        if 'otp' in st.session_state:
                            del st.session_state['otp']
                        if 'otp_time' in st.session_state:
                            del st.session_state['otp_time']
                else:
                    st.error("No OTP has been generated. Please refresh the page.")

# CAPTCHA verification function
def verify_captcha():
    st.subheader("CAPTCHA Verification")
    
    if 'captcha_text' not in st.session_state:
        captcha_text, captcha_image = generate_captcha()
        st.session_state['captcha_text'] = captcha_text
        st.session_state['captcha_image'] = captcha_image
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.image(st.session_state['captcha_image'])
        
        if st.button("Refresh CAPTCHA"):
            captcha_text, captcha_image = generate_captcha()
            st.session_state['captcha_text'] = captcha_text
            st.session_state['captcha_image'] = captcha_image
            st.rerun()
    
    with col2:
        user_captcha = st.text_input("Enter the CAPTCHA text shown in the image", max_chars=6)
        
        if st.button("Verify CAPTCHA"):
            if user_captcha.upper() == st.session_state['captcha_text']:
                st.success("CAPTCHA verified successfully!")
                st.session_state['captcha_verified'] = True
                time.sleep(1)
                st.rerun()
            else:
                st.error("Incorrect CAPTCHA. Please try again.")

# User registration function
def register_user():
    st.subheader("Register New User")
    
    with st.form("registration_form"):
        username = st.text_input("Username", key="reg_username")
        name = st.text_input("Full Name", key="reg_name")
        email = st.text_input("Email", key="reg_email")
        password = st.text_input("Password", type="password", key="reg_password")
        confirm_password = st.text_input("Confirm Password", type="password", key="reg_confirm_password")
        
        submitted = st.form_submit_button("Register")
        
        if submitted:
            if not username or not name or not email or not password:
                st.error("All fields are required")
                return
            
            if password != confirm_password:
                st.error("Passwords do not match")
                return
            
            users = load_users()
            
            if username in users:
                st.error("Username already exists")
                return
            
            # Create new user
            users[username] = {
                'name': name,
                'email': email,
                'password': hash_password(password)
            }
            
            save_users(users)
            st.success("Registration successful! You can now log in.")
            
            # Set session state to navigate to login on next rerun
            st.session_state['current_step'] = 'login'
            st.rerun()
    
    # This button is OUTSIDE the form
    if st.button("Back to Login"):
        st.session_state['current_step'] = 'login'
        st.rerun()

# User login function
def login_user():
    st.subheader("Login")
    
    col1, col2 = st.columns(2)
    
    with col1:
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        
        if st.button("Login"):
            users = load_users()
            
            if username not in users:
                st.error("Invalid username or password")
                return
            
            user_data = users[username]
            
            if not verify_password(user_data['password'], password):
                st.error("Invalid username or password")
                return
            
            st.success(f"Welcome {user_data['name']}! Proceeding to verification steps...")
            st.session_state['username'] = username
            st.session_state['name'] = user_data['name']
            st.session_state['current_step'] = 'captcha'
            time.sleep(1)
            st.rerun()
    
    with col2:
        st.info("Don't have an account?")
        if st.button("Register"):
            st.session_state['current_step'] = 'register'
            st.rerun()

# Main application
def main():
    st.title("🔐 Multi-Factor Authentication System")
    
    # Sidebar for app information
    with st.sidebar:
        st.header("About this App")
        st.info("""
        This application demonstrates a comprehensive multi-factor authentication system using:
        - Username/Password
        - CAPTCHA verification
        - One-Time Password (OTP)
        - Fingerprint Authentication
        
        For a real application, you would need to implement proper security measures and database integration.
        """)
        
        # Display authentication status
        st.subheader("Authentication Status")
        auth_status = {
            "Login": "✅" if st.session_state['username'] else "❌",
            "CAPTCHA": "✅" if st.session_state['captcha_verified'] else "❌",
            "OTP": "✅" if st.session_state['otp_verified'] else "❌",
            "Fingerprint": "✅" if st.session_state['fingerprint_verified'] else "❌"
        }
        
        for factor, status in auth_status.items():
            st.write(f"{factor}: {status}")
    
    # Main authentication flow
    if st.session_state['current_step'] == 'register':
        register_user()
    
    elif st.session_state['current_step'] == 'login':
        login_user()
    
    elif st.session_state['current_step'] == 'captcha':
        if not st.session_state['captcha_verified']:
            verify_captcha()
        else:
            st.session_state['current_step'] = 'otp'
            st.rerun()
    
    elif st.session_state['current_step'] == 'otp':
        if not st.session_state['otp_verified']:
            verify_otp()
        else:
            st.session_state['current_step'] = 'fingerprint'
            st.rerun()
    
    elif st.session_state['current_step'] == 'fingerprint':
        if not st.session_state['fingerprint_verified']:
            verify_fingerprint()
        else:
            st.session_state['current_step'] = 'authenticated'
            st.rerun()
    
    elif st.session_state['current_step'] == 'authenticated':
        # All authentication steps passed
        st.balloons()
        st.success(f"🎉 Authentication complete! Welcome, {st.session_state['name']}!")
        
        st.header("Protected Content")
        st.write("This is the protected area of the application that requires multi-factor authentication.")
        
        # Add your protected application content here
        st.write("You now have access to the secure features of this application.")
        
        # Logout button
        if st.button("Logout"):
            for key in ['authenticated', 'username', 'name', 'current_step', 
                        'captcha_verified', 'otp_verified', 'fingerprint_verified']:
                if key in st.session_state:
                    st.session_state[key] = False if key in ['authenticated', 'captcha_verified', 
                                                            'otp_verified', 'fingerprint_verified'] else None
            
            # Clear other session state variables if they exist
            for key in ['captcha_text', 'captcha_image', 'otp', 'otp_time']:
                if key in st.session_state:
                    del st.session_state[key]
            
            st.session_state['current_step'] = 'login'
            st.rerun()

if __name__ == "__main__":
    main()
