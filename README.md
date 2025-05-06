# Streamlit E-commerce Fraud Detection Demo

## Overview

This project is a demonstration platform showcasing an e-commerce application built with Streamlit. It features role-based access control (Admin, Seller, Buyer), a wallet system, product management, a shopping cart, user reviews, customer support tickets, and basic fraud detection mechanisms.

**Technologies Used:**
*   Frontend & Backend: Streamlit, Python
*   Database: MySQL
*   Password Hashing: bcrypt

## Features

*   **User Roles:** Distinct dashboards and functionalities for Admin, Seller, and Buyer roles.
*   **Authentication & Authorization:** Secure login and role-based access control.
*   **Product Management:** Sellers can perform CRUD (Create, Read, Update, Delete) operations on their products.
*   **Shopping Cart & Checkout:** Buyers can add products to a cart and proceed to checkout.
*   **Wallet System:** Buyers have a wallet balance, which Admins can adjust. Purchases deduct from the wallet.
*   **Review System:** Buyers can submit reviews for products they've purchased. Sellers can view reviews for their products.
*   **Customer Support Tickets:** Buyers can submit support tickets.
*   **Basic Fraud Detection:** Implements rules to flag potentially fraudulent activities, such as:
    *   Multiple failed login attempts.
    *   Orders exceeding a certain threshold amount.
    *   Rapid purchase velocity.
    *   Use of blacklisted payment methods (simulated).
*   **Anomaly Logging:** Suspicious activities are logged for review.
*   **User Blacklisting:** Admins can blacklist users, preventing them from logging in or making purchases.
*   **Activity Logging:** Key user actions are logged for auditing purposes.

## Database Schema

The database schema defining the structure for the 12 tables (e.g., `Users`, `Products`, `Orders`, `Cart`, `Wallet`, `Reviews`, `SupportTickets`, `FraudLog`, `Blacklist`, `ActivityLog`, etc.) is located in the `schema.sql` file.

## Dependencies

*   **Python Packages:** All required Python packages are listed in `requirements.txt`.
*   **Python Version:** Python 3.8 or higher is required.
*   **Database:** A running MySQL server instance is necessary.

## Setup Instructions

1.  **Clone the Repository:**
    ```bash
    git clone https://github.com/your-username/FraudDetectioninECommerce.git # Replace with actual URL if available
    ```
2.  **Navigate to Project Directory:**
    ```bash
    cd FraudDetectioninECommerce
    ```
3.  **Install Python:** Ensure you have Python 3.8+ installed. You can download it from [python.org](https://www.python.org/).
4.  **Set up MySQL Database:**
    *   Make sure your MySQL server is running.
    *   Connect to your MySQL server using a client (e.g., command line or MySQL Workbench):
        ```sql
        mysql -u root -p
        ```
    *   Create the database:
        ```sql
        CREATE DATABASE IF NOT EXISTS ecommerce_db;
        ```
    *   Select the database:
        ```sql
        USE ecommerce_db;
        ```
    *   Execute the schema file to create the tables:
        ```sql
        SOURCE schema.sql;
        -- Alternatively, open schema.sql in MySQL Workbench and execute it against the ecommerce_db.
        ```
5.  **Configure Environment Variables:**
    *   Create a `.env` file in the project root directory (you can copy `.env.example` if it exists).
    *   Add the following lines to the `.env` file, replacing the values if necessary:
        ```dotenv
        DB_HOST=localhost
        DB_PORT=3306
        DB_USER=root
        DB_PASSWORD=mysqls # Replace with your MySQL root password or the specific user's password
        DB_NAME=ecommerce_db
        ```
6.  **Install Python Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
7.  **Run the Seed Script:** This script populates the database with initial user accounts.
    ```bash
    python seed_users.py
    ```
    *   Check the console output to ensure the users were created successfully.

## Running the Application

1.  **Start the Streamlit App:**
    ```bash
    streamlit run app.py
    ```
2.  **Access the Application:** Open your web browser and navigate to the local URL provided by Streamlit (usually `http://localhost:8501`).
3.  **Initial Login Credentials:**
    *   **Admin:** `admin@example.com` / `AdminPass123`
    *   **Seller:** `seller@example.com` / `SellerPass123`
    *   **Buyer:** `buyer@example.com` / `BuyerPass123`

## Demonstration Steps

1.  Log in as the **Seller** (`seller@example.com`) and add a few products.
2.  Log out and log in as the **Buyer** (`buyer@example.com`).
3.  Add products to the cart and proceed to checkout.
4.  Attempt actions that might trigger fraud rules (e.g., make a very large purchase if a rule is set).
5.  Log in as the **Admin** (`admin@example.com`).
6.  Review fraud logs and activity logs.
7.  Adjust the Buyer's wallet balance if needed.
8.  Blacklist the Buyer user.
9.  Log out and attempt to log in as the (now blacklisted) **Buyer** - login should fail.
10. Attempt to make a purchase as the blacklisted Buyer (if login were possible) - checkout should be blocked.

## Troubleshooting

*   **Database Connection Errors:**
    *   Verify the `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, and `DB_NAME` in your `.env` file are correct.
    *   Ensure your MySQL server is running.
    *   Check if any firewall is blocking the connection to the MySQL port (default 3306).
*   **Module Not Found Errors:**
    *   Make sure you have activated the correct Python virtual environment (if using one).
    *   Run `pip install -r requirements.txt` again to ensure all dependencies are installed.
*   **Port Conflicts (Error: Port 8501 is already in use):**
    *   Stop any other Streamlit applications that might be running.
    *   Run the app on a different port: `streamlit run app.py --server.port 8502`
*   **Seed Script Errors (`seed_users.py`):**
    *   Check for database connection errors (see above).
    *   Ensure the database and tables were created successfully by running `SOURCE schema.sql;`.
    *   If you run the script multiple times, it might fail due to existing email addresses (unique constraint). You might need to clear the `Users` table before re-running if necessary.

## Deployment Guidance

This application requires a Python backend and a database, so it **cannot** be deployed using static hosting services like GitHub Pages.

**Suitable Deployment Platforms:**

*   **Streamlit Community Cloud:** Ideal for Streamlit apps. Requires connecting a GitHub repo and configuring secrets for `.env` variables. You'll also need a cloud-hosted MySQL database (e.g., PlanetScale, AWS RDS, Google Cloud SQL).
*   **Heroku:** Requires a `Procfile`, `runtime.txt`, and configuration for a database add-on.
*   **AWS Elastic Beanstalk:** Platform-as-a-Service offering more control.
*   **DigitalOcean App Platform:** Similar PaaS offering.
*   **Google Cloud Run:** Serverless container platform.

**Example: Streamlit Community Cloud**

1.  Push your project code (including `requirements.txt`, `app.py`, etc., but **not** `.env`) to a public or private GitHub repository.
2.  Sign up/log in to [Streamlit Community Cloud](https://share.streamlit.io/).
3.  Click "New app" and connect your GitHub account.
4.  Select the repository and branch containing your app code.
5.  Specify the main application file (`app.py`).
6.  In the "Advanced settings...", add your database credentials (`DB_HOST`, `DB_USER`, etc.) as Secrets. **Do not commit your `.env` file.** You will need to point `DB_HOST` to your cloud MySQL instance.
7.  Click "Deploy!". Streamlit Cloud will build and deploy your application.