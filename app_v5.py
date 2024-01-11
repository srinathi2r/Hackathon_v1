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
from passlib.hash import pbkdf2_sha256

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
    c.execute('CREATE TABLE IF NOT EXISTS users(first_name TEXT, last_name TEXT, email TEXT PRIMARY KEY, password TEXT)')

# ------------------------
# Authentication Functions
# ------------------------

def hash_password(password):
    """
    Hashes a password using pbkdf2_sha256 from passlib.
    Args:
    password (str): The password to be hashed.
    Returns:
    str: The hashed password.
    """
    return pbkdf2_sha256.hash(password)

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
    c = conn.cursor()
    hashed_password = hash_password(password)
    c.execute('INSERT INTO users (first_name, last_name, email, password) VALUES (?, ?, ?, ?)', (first_name, last_name, email, hashed_password))
    conn.commit()

def verify_login(email, password, conn):
    """
    Verifies a user's login credentials.
    Args:
    email (str): The email of the user.
    password (str): The password of the user.
    Returns:
    bool: True if login is successful, False otherwise.
    """
    c = conn.cursor()
    c.execute('SELECT password FROM users WHERE email = ?', (email,))
    user_data = c.fetchone()
    if user_data is None:
        return False
    hashed_password = user_data[0]
    return pbkdf2_sha256.verify(password, hashed_password)

def logout():
    """
    Handles the logout process, resetting relevant session state variables.
    """
    for key in ['logged_in', 'user_email', 'user_name']:
        if key in st.session_state:
            del st.session_state[key]
    st.session_state['just_logged_out'] = True

# ------------------------
# UI Component Functions
# ------------------------

def signup_form(conn):
    """
    Displays the sign-up form and handles new user registration.
    Args:
    conn: Database connection object.
    """
    st.subheader("Sign Up")
    first_name = st.text_input("First Name")
    last_name = st.text_input("Last Name")
    email = st.text_input("Email Address", max_chars=50)
    password = st.text_input("Password", type="password")
    if st.button("Sign Up"):
        add_user(conn, first_name, last_name, email, password)
        st.success("You have successfully signed up")

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

def add_product_form():
    """
    Displays a form for adding new products.
    """
    st.header("Add a Product")
    with st.form("product_form", clear_on_submit=True):
        brand = st.text_input("Brand")
        type_subtype = st.text_input("Type/Subtype")
        size = st.text_input("Size")
        cost = st.text_input("Cost")
        expiry_date = st.date_input("Expiry Date")
        classification = st.selectbox("Classification", ["Type 1", "Type 2", "Type 3"])
        location = st.text_input("Location/Cost Centre")
        uploaded_file = st.file_uploader("Upload Image", type=["jpg", "png"])
        submitted = st.form_submit_button("Submit Product")
        if submitted:
            st.success("Product Added")


def admin_view():
    """
    Displays the admin view for managing products.
    """
    st.header("Admin View")
    uploaded_file = st.file_uploader("Upload Excel File", type=["xlsx"])
    if uploaded_file:
        df = pd.read_excel(uploaded_file)
        st.write(df)
        

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


    st.title("The Reuseables/CodeRx-Renew")

    if 'logged_in' not in st.session_state or not st.session_state['logged_in']:
        login_form(conn)
    else:
        # Display user's name and logout button
        user_name = st.session_state.get('user_name', 'User')
        col1, col2 = st.columns([3, 1])
        col1.markdown(f"<h1 style='text-align: left; color: red;'>{user_name}</h1>", unsafe_allow_html=True)
        col2.button("Logout", on_click=logout)

        # Show tabs based on user role
        if st.session_state.get('user_email') == 'srinath.svce@gmail.com':
            tab1, tab2 = st.tabs(["📦 Add Product", "👨‍💼 Admin View"])
        else:
            tab1 = st.tabs(["📦 Add Product"])[0]

        with tab1:
            add_product_form()

        if st.session_state.get('user_email') == 'srinath.svce@gmail.com':
            with tab2:
                admin_view()

if __name__ == "__main__":
    main()
