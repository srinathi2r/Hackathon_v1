#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Jan 10 15:49:27 2024

@author: srinath
"""

import streamlit as st
import pandas as pd

# Function to display the user profile creation form
def create_user_profile():
    st.header("Create User Profile")
    phone_or_email = st.text_input("Phone number or Email")
    if st.button("Create Profile"):
        st.success("Profile created for: " + phone_or_email)

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
            # Append data to a CSV file
            product_data = {
                'Brand': brand,
                'Type/Subtype': type_subtype,
                'Size': size,
                'Cost': cost,
                'Expiry Date': expiry_date.strftime("%Y-%m-%d"),
                'Classification': classification,
                'Location/Cost Centre': location
                # Note: Handling image uploads requires additional steps
            }
            file_path = 'products.csv'
            if not os.path.isfile(file_path):
                pd.DataFrame([product_data]).to_csv(file_path, index=False)
            else:
                pd.DataFrame([product_data]).to_csv(file_path, mode='a', header=False, index=False)
            st.success("Product Added")

# Function to display the admin view
def admin_view():
    st.header("Admin View")
    try:
        uploaded_file = st.file_uploader("Upload Excel File", type=["xlsx"])
        if uploaded_file:
            df = pd.read_excel(uploaded_file)
            st.write(df)
            # Here you can add more functionality to process and display the data
    except Exception as e:
        st.error("Error loading Excel file")

# Layout of the app
def main():
    st.sidebar.title("Navigation")
    app_mode = st.sidebar.radio("Choose the mode", ["Create Profile", "Add Product", "Admin View"])

    if app_mode == "Create Profile":
        create_user_profile()
    elif app_mode == "Add Product":
        add_product_form()
    elif app_mode == "Admin View":
        admin_view()

if __name__ == "__main__":
    main()
