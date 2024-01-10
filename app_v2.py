#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Jan 10 17:09:01 2024

@author: srinath
"""

import streamlit as st
import pandas as pd
import os

file_name = 'style.css'
# Custom CSS to inject our own styles
def local_css(file_name):
    with open(file_name, "r") as f:
        st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)

# Function to display the user profile creation form
def create_user_profile():
    st.header("Create User Profile")
    phone_or_email = st.text_input("Phone number or Email", max_chars=50)
    if st.button("Create Profile"):
        st.success(f"Profile created for: {phone_or_email}")

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
    # Inject custom CSS for styling
    local_css("style.css")

    st.title("The Reuseables/CodeRx-Renew")

    tab1, tab2, tab3 = st.tabs(["Create Profile", "Add Product", "Admin View"])

    with tab1:
        create_user_profile()

    with tab2:
        add_product_form()

    with tab3:
        admin_view()

if __name__ == "__main__":
    main()
