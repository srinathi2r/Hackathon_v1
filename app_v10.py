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
                    user_name TEXT,
                    email TEXT PRIMARY KEY,
                    password TEXT,
                    is_email_verified BOOLEAN DEFAULT FALSE)''')

def add_user_name_to_users_table(conn, user_name):
    """
    Adds the 'user_name' field to the 'users' table.
    Args:
    conn: Database connection object.
    user_name (str): The user's name.
    """
    c = conn.cursor()
    c.execute('ALTER TABLE users ADD COLUMN user_name TEXT')
    c.execute('UPDATE users SET user_name = ? WHERE email = ?', (user_name, st.session_state['user_email']))
    conn.commit()

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
                    user_name TEXT,  -- Add a column for user_name (or user_id)
                    item_name TEXT,
                    brand TEXT,
                    type_subtype TEXT,
                    size TEXT,
                    cost REAL,
                    quantity TEXT,
                    expiry_date DATE,
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

def add_user(conn, first_name, last_name, email, password, user_name):
    """
    Adds a new user to the database.
    Args:
    conn: Database connection object.
    first_name (str): The first name of the user.
    last_name (str): The last name of the user.
    email (str): The email of the user.
    password (str): The password of the user.
    user_name (str): The user's full name.
    """
    # Log the inputs
    print("Sign-up Inputs - Email:", email, "Password:", password)  # Be cautious with password logging

    c = conn.cursor()
    hashed_password = hash_password(password)
    c.execute('INSERT INTO users (first_name, last_name, email, password, is_email_verified, user_name) VALUES (?, ?, ?, ?, ?, ?)',
              (first_name, last_name, email, hashed_password, 0, user_name))  # Set is_email_verified to 0 for new users
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
    Returns:
    str: The generated user_name.
    """
    st.subheader("Sign Up")
    first_name = st.text_input("First Name")
    last_name = st.text_input("Last Name")
    email = st.text_input("Email Address", max_chars=50)
    user_name = f"{first_name} {last_name}"  # Generate user_name from first_name and last_name
    password = st.text_input("Password", type="password")

    verification_code_input_visible = False  # Flag to control the visibility of the verification code input
    verification_success = None  # Initialize verification success flag
    verification_code = generate_verification_code()  # Generate the verification code

    if st.button("Sign Up"):
        add_user(conn, first_name, last_name, email, password, user_name)  # Pass user_name to add_user
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

    # Return the generated user_name
    return user_name



def login_form(conn):
    """
    Displays the login form and handles user authentication.
    """
    st.subheader("Login")
    email = st.text_input("Email Address", max_chars=50, key=f"login_email")
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

import os

# Define the directory where uploaded images will be saved
UPLOAD_DIR = "uploads"  # You can change this to your desired directory path

def add_product_form(conn, user_name):
    """
    Displays a form for adding new products and inserts them into the database.
    Args:
    conn: Database cursor object.
    user_name (str): The name of the user adding the product.
    """
    st.header("Add a Product")
    with st.form("product_form", clear_on_submit=True):
        item_name = st.text_input("Item Name")
        brand = st.text_input("Brand")
        type_subtype = st.text_input("Type/Subtype")
        size = st.text_input("Size")
        cost = st.number_input("Cost", step=0.01)
        quantity = st.text_input("Quantity")
        expiry_date = st.date_input("Expiry Date")
        location = st.text_input("Location/Cost Centre")
        uploaded_file = st.file_uploader("Upload Image", type=["jpg", "png"])

        submitted = st.form_submit_button("Submit Product")
        
        if submitted:
            try:
                # Save the uploaded image to the UPLOAD_DIR directory
                if uploaded_file is not None:
                    image_path = os.path.join(UPLOAD_DIR, uploaded_file.name)
                    with open(image_path, "wb") as image_file:
                        image_file.write(uploaded_file.read())
                else:
                    image_path = None
                
                # Insert the product details into the database
                c = conn.cursor()
                c.execute('INSERT INTO products (user_name, item_name, brand, type_subtype, size, cost, quantity, expiry_date, location, image_path) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                          (user_name, item_name, brand, type_subtype, size, cost, quantity, expiry_date, location, image_path))
                conn.commit()  # Commit the changes to the database
                st.success("Product Added")
            except Exception as e:
                st.error(f"Error adding product to database: {str(e)}")
        return submitted  # Return the submitted value

        # Check if the form has not been submitted, and don't display success message
        if not submitted:
            st.empty()  # Empty element to avoid displaying "None"

        

def admin_view_by_users(conn):
    """
    Displays the admin view by users and their products sorted by user name.
    """
    st.header("Admin View by Users (Sorted by User Name)")

    # Fetch products data sorted by user name
    c = conn.cursor()
    c.execute('SELECT user_name, item_name, brand, type_subtype, size, cost, quantity, expiry_date, location, image_path FROM products ORDER BY user_name')
    products_data = c.fetchall()

    if products_data:
        current_user_name = None
        for product in products_data:
            user_name, item_name, brand, type_subtype, size, cost, quantity, expiry_date, location, image_path = product
            if user_name != current_user_name:
                st.subheader(f"User: {user_name}")
                current_user_name = user_name

            # Display the product information
            st.markdown(f"**Product Name:** {item_name}")
            st.markdown(f"**Expiry Date:** {expiry_date}")
            st.image(image_path, use_column_width=True)  # Display product image
            st.write(f"Brand: {brand}")
            st.write(f"Type/Subtype: {type_subtype}")
            st.write(f"Size: {size}")
            st.write(f"Cost: {cost}")
            st.write(f"Quantity: {quantity}")
            st.write(f"Location/Cost Centre: {location}")
            st.write("--------------------------------------------------")
    else:
        st.info("No products available.")



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
    Displays a table of products from the database.
    Args:
    conn: Database cursor object.
    """
    st.header("Products List")
    c = conn.cursor()
    # Update the SQL query to retrieve user details using user_name
    c.execute('''
    SELECT products.*, users.user_name, users.first_name, users.last_name 
    FROM products
    JOIN users ON products.user_name = users.user_name
    ''')

    products_data = c.fetchall()

    if not products_data:
        st.warning("No products found.")
    else:
        # Create a DataFrame with the retrieved data
        products_df = pd.DataFrame(products_data, columns=["ID", "User Name", "Item Name", 
                                                           "Brand", "Type/Subtype", "Size", 
                                                           "Cost", "Quantity", "Expiry Date",
                                                           "Location", "Image Path", 
                                                           "First Name", "Last Name", "user_name"])
        st.dataframe(products_df)


def add_product(conn):
    """
    Displays a form for adding new products and inserts them into the database.
    """
    st.header("Add a Product")
    with st.form("product_form", clear_on_submit=True):
        item_name = st.text_input("Item Name")
        brand = st.text_input("Brand")
        type_subtype = st.text_input("Type/Subtype")
        size = st.text_input("Size")
        cost = st.number_input("Cost", step=0.01)
        quantity = st.text_input("Quantity")
        expiry_date = st.date_input("Expiry Date")
        location = st.text_input("Location/Cost Centre")
        uploaded_file = st.file_uploader("Upload Image", type=["jpg", "png"])
        submitted = st.form_submit_button("Submit Product")
        
        if submitted:
            # Insert the product details into the database
            c = conn.cursor()
            c.execute('INSERT INTO products (item_name, brand, type_subtype, size, cost, quantity, expiry_date, location, image_path) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                      (item_name, brand, type_subtype, size, cost, quantity, expiry_date, location, uploaded_file))
            conn.commit()
            st.success("Product Added")

        # Check if the form has not been submitted, and don't display success message
        if not submitted:
            st.empty()  # Empty element to avoid displaying "None"


def detect_device_type():
    user_agent_string = st.experimental_get_query_params().get("user_agent", [None])[0]

    # Debugging: Log the user agent string
    st.write("User Agent String:", user_agent_string)

    if user_agent_string:
        if any(keyword in user_agent_string.lower() for keyword in ["mobile", "tablet", "android", "iphone", "ipad"]):
            return "Phone or Tablet"
    
    return "Computer"

# ------------------------
# Main App Logic
# ------------------------
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
        login_form(conn)  # Display the login form
    else:
        user_name = st.session_state.get('user_name', 'User')
        
        col1, col2 = st.columns([3, 1])
        col1.markdown(f"<h1 style='text-align: left; color: red;'>{user_name}</h1>", unsafe_allow_html=True)
        col2.button("Logout", on_click=logout)

        if st.session_state.get('user_email') == 'srinath.svce@gmail.com':
            tab1, tab2 = st.tabs(["📦 Add Product", "👨‍💼 Admin View"])
            with tab1:
                if add_product_form(conn, user_name):  # Pass the user name to the form
                    display_products(conn)  # Refresh the products list after a new product is added

            with tab2:
                admin_view_by_users(conn)  # Display the admin view by users and their products

        else:
            tab1 = st.tabs(["📦 Add Product"])[0]
            with tab1:
                if add_product_form(conn, user_name):  # Pass the user name to the form
                    display_products(conn)  # Refresh the products list after a new product is added

         

if __name__ == "__main__":
    main()
