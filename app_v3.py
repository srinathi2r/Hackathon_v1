#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Jan 10 22:18:42 2024

@author: srinath
"""

import streamlit as st
import pandas as pd

# Custom CSS to inject our own styles
def local_css(file_name):
    with open(file_name) as f:
        st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)

# Function to display the sign-up form
def signup_form():
    st.subheader("Sign Up")
    username = st.text_input("Username", max_chars=50, key="signup_username")
    email = st.text_input("Email Address", max_chars=50, key="signup_email")
    password = st.text_input("Password", type="password", key="signup_password")
    if st.button("Sign Up"):
        st.success(f"Account created for: {username}")

# Function to display the login form
def login_form():
    st.subheader("Login")
    username = st.text_input("Username", key="login_username")
    password = st.text_input("Password", type="password", key="login_password")
    if st.button("Login"):
        st.success(f"Logged in as {username}")

    # Toggle to show/hide the signup form
    if st.checkbox("New users: Click here to Sign Up"):
        signup_form()

# Function to display the product entry form
def add_product_form():
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

# Function to display the admin view
def admin_view():
    st.header("Admin View")
    uploaded_file = st.file_uploader("Upload Excel File", type=["xlsx"])
    if uploaded_file:
        df = pd.read_excel(uploaded_file)
        st.write(df)


# Main app layout
def main():
    local_css("style.css")

    st.title("The Reuseables/CodeRx-Renew")
    
    # Using emojis for simple icons
    with st.container():
        tab1, tab2, tab3 = st.tabs([
            f"🔐 Login",
            f"📦 Add Product",
            f"👨‍💼 Admin View"
        ])

    with tab1:
        login_form()

    with tab2:
        add_product_form()

    with tab3:
        admin_view()

if __name__ == "__main__":
    main()
