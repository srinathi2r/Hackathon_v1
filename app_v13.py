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
import random
import matplotlib.pyplot as plt
from datetime import datetime, timedelta

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
    Displays visualizations for the admin view, including cost saved by location and mock transaction data.
    """
    st.header("Admin View")

    # Fetch and visualize cost data by location
    c = conn.cursor()
    c.execute('SELECT location, SUM(cost) AS total_cost FROM products GROUP BY location')
    cost_data = c.fetchall()

    if cost_data:
        cost_df = pd.DataFrame(cost_data, columns=["location", "Total Cost"])
        fig, ax = plt.subplots()
        bars = ax.bar(cost_df['location'], cost_df['Total Cost'])

        # Add enhanced labels on each bar
        for bar in bars:
            yval = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2, yval, f"${round(yval, 2)}", 
                    va='bottom', ha='center', 
                    color='brown', fontweight='bold', fontsize=12)  # Adjust color, weight, and size as needed

        ax.set_xlabel('Location')
        ax.set_ylabel('Total Cost')
        st.subheader("Potential Cost Saved by Department")
        st.pyplot(fig)
    else:
        st.info("No location-based cost data available.")

    # Generate mock transaction data for specified locations
    locations = ["OT", "DS Ward", "SICU", "ED"]
    products = ["Lipofundin", "CPR Stat Padz", "ETT"]  # Replace with actual product names if desired
    transaction_df = generate_mock_transaction_data(locations, products)
    most_frequent_df = find_most_frequent_items(transaction_df)

    # Display mock transaction data visualization
    st.subheader("Most Frequently Bought and Sold Items by Department")
    plot_most_frequent_transactions(most_frequent_df)

# Make sure to define the functions `generate_mock_transaction_data`, `find_most_frequent_items`, and `plot_most_frequent_transactions` as shown in the previous messages.


def logout():
    """
    Handles the logout process, resetting relevant session state variables.
    """
    for key in ['logged_in', 'user_email', 'user_name']:
        if key in st.session_state:
            del st.session_state[key]
    st.session_state['just_logged_out'] = True


def generate_mock_transaction_data(locations, products, max_count=20):
    """
    Generates mock transaction data for illustration purposes.
    Args:
    locations (list): List of locations.
    products (list): List of product names.
    max_count (int): Maximum number of transactions for a product at a location.
    Returns:
    DataFrame: A DataFrame with simulated transaction data.
    """
    data = []
    for location in locations:
        for product in products:
            buy_count = random.randint(0, max_count)
            sell_count = random.randint(0, max_count)
            data.append([location, product, buy_count, sell_count])
    return pd.DataFrame(data, columns=["Location", "Product", "Buy Count", "Sell Count"])

def find_most_frequent_items(df):
    """
    Finds the most frequently bought and sold items for each location.
    Args:
    df (DataFrame): DataFrame containing transaction data.
    Returns:
    DataFrame: A DataFrame with the most frequent buy and sell for each location.
    """
    most_frequent = df.groupby(['Location', 'Product']).sum()
    most_frequent = most_frequent.sort_values(['Location', 'Buy Count', 'Sell Count'], ascending=False).reset_index()
    most_frequent = most_frequent.drop_duplicates(subset='Location', keep='first')
    return most_frequent[['Location', 'Product', 'Buy Count', 'Sell Count']]


def plot_most_frequent_transactions(df):
 """
 Plots the most frequently bought and sold items for each location.
 Args:
 df (DataFrame): DataFrame containing the most frequent items data.
 """
 fig, ax = plt.subplots(figsize=(10, 6))

 # Bar plot for each location
 locations = df['Location'].unique()
 for loc in locations:
     loc_data = df[df['Location'] == loc]
     ax.bar(loc + ' - Buy', loc_data['Buy Count'].values[0], color='blue')
     ax.bar(loc + ' - Sell', loc_data['Sell Count'].values[0], color='red')

 ax.set_xlabel('Location and Transaction Type')
 ax.set_ylabel('Transaction Count')
 ax.set_title('Most Frequently Bought and Sold Items per Location')
 ax.legend(['Buy', 'Sell'], loc='upper right')
 plt.xticks(rotation=45)
 st.pyplot(fig)
 
    
def display_products(conn, context=""):
    """
    Displays a table of products from the database. Each product can be expanded to view more details in a two-column layout.
    Args:
    conn: Database cursor object.
    """
    st.header("Products List")
    search_query = st.text_input("Search by Item Name, Brand or Type/Subtype", key=f"product_search_{context}")

    c = conn.cursor()
    query = '''
    SELECT id, item_name, brand, type_subtype, size, cost, quantity, expiry_date, location, image_path 
    FROM products
   '''
    if search_query:
        query += " WHERE item_name LIKE ? OR brand LIKE ? OR type_subtype LIKE ?"
        search_query = f'%{search_query}%'
        c.execute(query, (search_query, search_query, search_query))
    else:
        c.execute(query)
    products_data = c.fetchall()

    if not products_data:
        st.warning("No products found.")
    else:
        for product in products_data:
            product_id, item_name, brand, type_subtype, size, cost, quantity, expiry_date, location, image_path = product
            with st.expander(f"{item_name}"):
                col1, col2 = st.columns([3, 2])

                # Column for Image
                with col1:
                    st.image(image_path, caption=item_name, width=300)

                # Column for Details
                with col2:
                    st.text(f"Brand: {brand}")
                    st.text(f"Type/Subtype: {type_subtype}")
                    st.text(f"Size: {size}")
                    st.text(f"Cost: {cost}")
                    st.text(f"Quantity: {quantity}")
                    st.text(f"Expiry Date: {expiry_date}")
                    st.text(f"Location: {location}")
                    expiry_status_html = get_expiry_status(expiry_date)
                    st.markdown(f"Expiry Date: {expiry_date} {expiry_status_html}", unsafe_allow_html=True)
   
                # Contact Seller Button
                st.button("Contact Seller", key=f"contact_{product_id}_{context}")


def get_expiry_status(expiry_date_str):
    """
    Determines the expiry status of a product based on its expiry date.
    Args:
    expiry_date_str: Expiry date as a string.
    Returns:
    str: HTML formatted expiry status.
    """
    try:
        expiry_date_obj = datetime.strptime(expiry_date_str, '%Y-%m-%d')
        current_date = datetime.now()

        if expiry_date_obj < current_date:
            # Red and bold for expired products
            return "<span style='color: red; font-weight: bold;'> (Expired)</span>"
        elif expiry_date_obj <= current_date + timedelta(days=7):
            # Orange and bold for products expiring soon
            return "<span style='color: orange; font-weight: bold;'> (Going to expire soon)</span>"
        else:
            return ""
    except ValueError:
        return ""  # Return empty string in case of invalid date format

    
def show_product_details_popup(product):
    """
    Displays the details of the clicked product in a popup, including expiry status.
    Args:
    product: The product details as a Series or dict.
    """
    expiry_status = get_expiry_status(product['Expiry Date'])

    with st.expander("Product Details", expanded=True):
        st.image(product['Image Path'], caption=product['Item Name'], width=200)
        st.text(f"Brand: {product['Brand']}")
        st.text(f"Type/Subtype: {product['Type/Subtype']}")
        st.text(f"Size: {product['Size']}")
        st.text(f"Cost: {product['Cost']}")
        st.text(f"Quantity: {product['Quantity']}")
        st.text(f"Expiry Date: {product['Expiry Date']} {expiry_status}")
        st.text(f"Location: {product['Location']}")
        st.button("Contact Seller", key=f"contact_{product['ID']}")  # Placeholder for Contact Seller button
        if st.button("Close", key=f"close_{product['ID']}"):
            # Logic to close the popup
            st.experimental_rerun()

def show_product_details_popup(product):
    """
    Displays the details of the clicked product in a popup.
    Args:
    product: The product details as a Series or dict.
    """
    with st.expander("Product Details", expanded=True):
        col1, col2, col3 = st.columns([3, 3, 2])  # Adjust column ratios for better spacing

        # Column for Image
        with col1:
            st.image(product['Image Path'], caption=product['Item Name'], width=250)  # Further increase image width

        # Column for Details
        with col2:
            st.subheader(product['Item Name'])
            st.text(f"Brand: {product['Brand']}")
            st.text(f"Type/Subtype: {product['Type/Subtype']}")
            st.text(f"Size: {product['Size']}")
            st.text(f"Cost: {product['Cost']}")
            st.text(f"Quantity: {product['Quantity']}")
            st.text(f"Expiry Date: {product['Expiry Date']}")
            st.text(f"Location: {product['Location']}")

        # Column for Buttons
        with col3:
            # Custom CSS to reduce the font size of the button
            st.markdown("<style>.small-font { font-size:10px !important; }</style>", unsafe_allow_html=True)
            if st.button("Contact Seller", key=f"contact_{product['ID']}"):
                # Logic for Contact Seller button (Placeholder)
                pass
            if st.button("Close", key=f"close_{product['ID']}"):
                # Logic to close the popup
                st.experimental_rerun()

def load_custom_css():
    """
    Load custom CSS styles.
    """
    custom_css = """
    <style>
        /* Custom styles for buttons */
        .stButton>button {
            font-size: 10px;  /* Adjust the font size */
            padding: 4px 12px;  /* Adjust padding to make button smaller */
        }
    </style>
    """
    st.markdown(custom_css, unsafe_allow_html=True)


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
def main():
    local_css("style.css")
    load_custom_css()
    with sqlite3.connect('users.db') as conn:
        create_users_table(conn)
        create_verification_table(conn)
        create_products_table(conn)  # Create the products table

    st.title("The Reuseables/CodeRx-Renew")

    if 'logged_in' not in st.session_state or not st.session_state['logged_in']:
        login_form(conn)  # Display the login form
    else:
        user_name = st.session_state.get('user_name', 'User')
        col1, col2 = st.columns([3, 1])
        col1.markdown(f"<h1 style='text-align: left; color: red;'>Welcome, {user_name}</h1>", unsafe_allow_html=True)
        col2.button("Logout", on_click=logout)

        if st.session_state.get('user_email') == 'srinath.svce@gmail.com':
            # Admin user tabs
            tab1, tab2, tab3 = st.tabs(["📦 View Products", "➕ Add Product", "👨‍💼 Admin View"])
            with tab1:
                display_products(conn)
            with tab2:
                add_product_form(conn, user_name)  # Removed display_products from here
            with tab3:
                admin_view_by_users(conn)
        else:
            # Regular user tabs
            tab1, tab2 = st.tabs(["📦 View Products", "➕ Add Product"])
            with tab1:
                display_products(conn)
            with tab2:
                add_product_form(conn, user_name)  # Removed display_products from here

if __name__ == "__main__":
    main()
