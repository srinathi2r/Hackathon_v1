#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Jan 10 22:18:42 2024
@author: srinath

A Streamlit app for managing products and admin functionalities. It includes user authentication
(signup and login), product management, and admin view functionalities. Admin users can access
additional features.
"""

import streamlit as st
import pandas as pd
import sqlite3
import bcrypt
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
import os
import uuid

# ------------------------
# Custom CSS Styling
# ------------------------

def local_css(file_name):
    """
    Injects custom CSS styles into the Streamlit app.
    Args:
    file_name (str): The file name of the CSS file.
    """
    with open(file_name) as f:
        st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)

# ------------------------
# Database-related Functions
# ------------------------

def create_users_table(conn):
    """
    Creates a 'users' table in the SQLite database if it doesn't already exist.
    """
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users(
                    first_name TEXT,
                    last_name TEXT,
                    email TEXT PRIMARY KEY,
                    password TEXT,
                    is_email_verified BOOLEAN DEFAULT FALSE)''')

def create_verification_table(conn):
    """
    Creates a table for storing email verification tokens.
    """
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS verification_tokens(email TEXT PRIMARY KEY, token TEXT)')

def create_products_table(conn):
    """
    Creates a 'products' table in the SQLite database if it doesn't already exist.
    """
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS products(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    brand TEXT,
                    type_subtype TEXT,
                    size TEXT,
                    cost REAL,
                    expiry_date DATE,
                    classification TEXT,
                    location TEXT,
                    image_path TEXT)''')

# ------------------------
# Authentication Functions
# ------------------------

# Accessing the SendGrid API key from an environment variable
SENDGRID_API_KEY = os.getenv('SENDGRID_API_KEY')

def send_verification_email(email, verification_code):
    """
    Sends a verification email to the user with a verification code.
    Args:
    email (str): The email address to send to.
    verification_code (str): The verification code to include in the email.
    """
    message = Mail(
        from_email='srinath.svce@gmail.com',
        to_emails=email,
        subject='Verify your email',
        html_content=f'Please verify your email by entering this code: {verification_code}')

    try:
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        response = sg.send(message)  # Send the email
        print("Email Sent. Response:")
        print(response.status_code)
        print(response.body)
        print(response.headers)
    except Exception as e:
        print("Email Send Error:", e.message)

def generate_verification_code():
    """
    Generates a unique verification code.
    """
    return str(uuid.uuid4())[:8]  # Example: 8-character unique code

def verify_user_email(conn, email):
    c = conn.cursor()
    c.execute('UPDATE users SET is_email_verified = ? WHERE email = ?', (True, email))
    conn.commit()
    print(f"Email Verified for user with email: {email}")

def hash_password(password):
    """
    Hashes a password using bcrypt.
    Args:
    password (str): The password to be hashed.
    Returns:
    bytes: The hashed password.
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def add_user(conn, first_name, last_name, email, password):
    """
    Adds a new user to the database.
    Args:
    conn: Database connection object.
    first_name (str): The first name of the user.
    last_name (str): The last name of the user.
    email (str): The email of the user.
    password (str): The password of the user.
    """
    # Log the inputs
    print("Sign-up Inputs - Email:", email, "Password:", password)  # Be cautious with password logging

    c = conn.cursor()
    hashed_password = hash_password(password)
    c.execute('INSERT INTO users (email, password, is_email_verified) VALUES (?, ?, ?)',
              (email, hashed_password, 0))  # Set is_email_verified to 0 for new users
    conn.commit()
    print(f"User added with email: {email}")

def verify_login(email, password, conn):
    """
    Verifies a user's login credentials and checks if the email is verified.
    Args:
    email (str): The email of the user.
    password (str): The password of the user.
    conn: Database connection object.
    Returns:
    bool: True if login is successful and email is verified, False otherwise.
    """
    # Log the inputs
    print("Login Inputs - Email:", email, "Password:", password)  # Be cautious with password logging

    c = conn.cursor()
    c.execute('SELECT password, is_email_verified FROM users WHERE email = ?', (email,))
    user_data = c.fetchone()
    if user_data is None:
        return False
    hashed_password, is_email_verified = user_data
    print(password.encode('utf-8'))
    print(hashed_password)
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password) and is_email_verified

def verify_email_code(conn, email, verification_code):
    """
    Verifies the email based on the entered verification code.
    Args:
    conn: Database connection object.
    email (str): The email of the user.
    verification_code (str): The verification code entered by the user.
    Returns:
    bool: True if the verification is successful, False otherwise.
    """
    print("Verifying email code...")
    c = conn.cursor()
    
    print(f"Received email: {email}")
    print(f"Received verification code: {verification_code}")

    # Fetch the token from the database for the given email
    c.execute('SELECT token FROM verification_tokens WHERE email = ?', (email,))
    token_data = c.fetchone()
    
    if token_data:
        fetched_token = token_data[0]
        print(f"Fetched token from the database: {fetched_token}")

    # Check if the fetched token matches the verification code
    if token_data and fetched_token == verification_code:
        # Update the is_email_verified field in the database
        c.execute('UPDATE users SET is_email_verified = ? WHERE email = ?', (True, email))
        conn.commit()
        print(f"Email Verified for user with email: {email}")
        return True
    else:
        print(f"Invalid verification code for user with email: {email}")
        return False


# ------------------------
# UI Component Functions
# ------------------------
def signup_form(conn):
    """
    Displays the sign-up form and handles new user registration.
    """
    st.subheader("Sign Up")
    first_name = st.text_input("First Name")
    last_name = st.text_input("Last Name")
    email = st.text_input("Email Address", max_chars=50)
    password = st.text_input("Password", type="password")

    verification_code_input_visible = False  # Flag to control the visibility of the verification code input
    verification_success = None  # Initialize verification success flag
    verification_code = generate_verification_code()  # Generate the verification code

    if st.button("Sign Up"):
        add_user(conn, first_name, last_name, email, password)
        send_verification_email(email, verification_code)
        verification_code_input_visible = True  # Set the flag to True

    if verification_code_input_visible:
        verification_code_input = st.text_input("Verification Code")
        if st.button("Verify Code"):
            print("Verify Code button clicked")  # Debugging statement
            if verify_email_code(conn, email, verification_code_input):  # Call the verify_email_code function
                print("Email verified successfully")  # Debugging statement
                verification_success = True
            else:
                print("Email verification failed")  # Debugging statement
                verification_success = False

    # Check verification success and provide appropriate message
    if verification_success is True:
        st.success("Email verified successfully!")
        st.markdown("You have successfully signed up. Please proceed to the login page.")
    elif verification_success is False:
        st.error("Invalid verification code. Please try again.")



def login_form(conn):
    """
    Displays the login form and handles user authentication.
    """
    st.subheader("Login")
    email = st.text_input("Email Address", max_chars=50, key="login_email")
    password = st.text_input("Password", type="password", key="login_password")
    login_attempted = st.button("Login", key="login_button")
    c = conn.cursor()

    if login_attempted:
        if verify_login(email, password, conn):
            # Update session state upon successful login
            st.session_state['logged_in'] = True
            st.session_state['user_email'] = email
            # Retrieve and set the user's name for display
            c.execute('SELECT first_name, last_name FROM users WHERE email = ?', (email,))
            user_data = c.fetchone()
            if user_data:
                st.session_state['user_name'] = f"{user_data[0]} {user_data[1]}"
            # Use st.experimental_rerun to refresh the app immediately after login
            st.experimental_rerun()
        else:
            st.error("Invalid email or password")

    # Toggle to show/hide the signup form
    if st.checkbox("New users: Click here to Sign Up"):
        signup_form(conn)

def add_product_form(c):
    """
    Displays a form for adding new products and inserts them into the database.
    Args:
    c: Database cursor object.
    """
    st.header("Add a Product")
    with st.form("product_form", clear_on_submit=True):
        brand = st.text_input("Brand")
        type_subtype = st.text_input("Type/Subtype")
        size = st.text_input("Size")
        cost = st.number_input("Cost", step=0.01)
        expiry_date = st.date_input("Expiry Date")
        classification = st.selectbox("Classification", ["Type 1", "Type 2", "Type 3"])
        location = st.text_input("Location/Cost Centre")
        uploaded_file = st.file_uploader("Upload Image", type=["jpg", "png"])
        submitted = st.form_submit_button("Submit Product")
        
        if submitted:
            # Insert the product details into the database
            c.execute('INSERT INTO products (brand, type_subtype, size, cost, expiry_date, classification, location, image_path) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                      (brand, type_subtype, size, cost, expiry_date, classification, location, uploaded_file))
            st.success("Product Added")

        return submitted  # Return the submitted value


# Rest of your code...


def admin_view():
    """
    Displays the admin view for managing products.
    """
    st.header("Admin View")
    uploaded_file = st.file_uploader("Upload Excel File", type=["xlsx"])
    if uploaded_file:
        df = pd.read_excel(uploaded_file)
        st.write(df)

def logout():
    """
    Handles the logout process, resetting relevant session state variables.
    """
    for key in ['logged_in', 'user_email', 'user_name']:
        if key in st.session_state:
            del st.session_state[key]
    st.session_state['just_logged_out'] = True
    
    
def display_products(conn):
    """
    Displays the list of products in a tabular format.
    """
    st.header("Products")
    
    # Fetch product data from the database
    c = conn.cursor()
    c.execute('SELECT * FROM products')
    products_data = c.fetchall()
    
    if products_data:
        # Create a DataFrame from the fetched data
        products_df = pd.DataFrame(products_data, columns=["ID", "Brand", "Type/Subtype", "Size", "Cost", "Expiry Date", "Classification", "Location", "Image Path"])
        # Display the DataFrame as a table
        st.dataframe(products_df)
    else:
        st.info("No products available.")

def add_product(conn):
    """
    Displays a form for adding new products and inserts them into the database.
    """
    st.header("Add a Product")
    with st.form("product_form", clear_on_submit=True):
        brand = st.text_input("Brand")
        type_subtype = st.text_input("Type/Subtype")
        size = st.text_input("Size")
        cost = st.number_input("Cost", step=0.01)
        expiry_date = st.date_input("Expiry Date")
        classification = st.selectbox("Classification", ["Type 1", "Type 2", "Type 3"])
        location = st.text_input("Location/Cost Centre")
        uploaded_file = st.file_uploader("Upload Image", type=["jpg", "png"])
        submitted = st.form_submit_button("Submit Product")
        
        if submitted:
            # Insert the product details into the database
            c = conn.cursor()
            c.execute('INSERT INTO products (brand, type_subtype, size, cost, expiry_date, classification, location, image_path) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                      (brand, type_subtype, size, cost, expiry_date, classification, location, uploaded_file))
            conn.commit()
            st.success("Product Added")

        # Check if the form has not been submitted, and don't display success message
        if not submitted:
            st.empty()  # Empty element to avoid displaying "None"


def detect_device_type():
    # Get the user agent string from the query parameters
    user_agent_string = st.experimental_get_query_params().get("user_agent", [None])[0]

    if user_agent_string:
        # Check if the user agent string contains keywords for mobile or tablet devices
        if any(keyword in user_agent_string.lower() for keyword in ["mobile", "tablet", "android", "iphone", "ipad"]):
            return "Phone or Tablet"
    
    # Default to "Computer" if the user agent is not detected as mobile or tablet
    return "Computer"

# ------------------------
# Main App Logic
# ------------------------

# ...

def main():
    """
    Main function to set up the Streamlit app layout.
    """
    local_css("style.css")
    with sqlite3.connect('users.db') as conn:
        create_users_table(conn)
        create_verification_table(conn)
        create_products_table(conn)  # Create the products table

    st.title("The Reuseables/CodeRx-Renew")

    # Detect the device type
    device_type = detect_device_type()
    
    # Display the result in brown color
    st.markdown(f"<p style='position: absolute; top: 10px; right: 10px; color: brown; font-size: 12px;'>{device_type}</p>", unsafe_allow_html=True)

    if 'logged_in' not in st.session_state or not st.session_state['logged_in']:
        login_form(conn)
    else:
        user_name = st.session_state.get('user_name', 'User')
        col1, col2 = st.columns([3, 1])
        col1.markdown(f"<h1 style='text-align: left; color: red;'>{user_name}</h1>", unsafe_allow_html=True)
        col2.button("Logout", on_click=logout)

        if st.session_state.get('user_email') == 'srinath.svce@gmail.com':
            tab1, tab2 = st.tabs(["📦 Add Product", "👨‍💼 Admin View"])
        else:
            tab1 = st.tabs(["📦 Add Product"])[0]

        with tab1:
            add_product_form(conn)  # Display the add product form (modified)
            display_products(conn)  # Display the list of products

if __name__ == "__main__":
    main()


if __name__ == "__main__":
    main()