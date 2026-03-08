"""
Authentication module for Streamlit app
---------------------------------------
Features:
- SQLite user database
- Admin + viewer roles
- Registration
- Login (via streamlit-authenticator)
- Password reset
- Secure bcrypt hashing
"""

import streamlit as st
import streamlit_authenticator as stauth
import sqlite3
import bcrypt

# ==========================
# CONFIG
# ==========================

DB_FILE = "users.db"
SIGNATURE_KEY = "simple_auth_key_12345"


# ==========================
# DATABASE INITIALIZATION
# ==========================

def init_users_db():
    """Create users table if it does not exist."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            role TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()


# ==========================
# USER RETRIEVAL
# ==========================

def load_users_from_db():
    """
    Load all users in the format required by streamlit-authenticator.
    Returns:
        dict: {username: {name, password, email, role}}
    """
    init_users_db()

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("SELECT username, name, password, email, role FROM users")
    rows = cursor.fetchall()
    conn.close()

    users = {}
    for username, name, password, email, role in rows:
        users[username] = {
            "name": name,
            "password": password,
            "email": email or f"{username}@example.com",
            "role": role or "viewer"
        }

    return users


def get_all_users():
    """Return list of all users with basic info."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("SELECT username, name, role FROM users ORDER BY created_at DESC")
    users = cursor.fetchall()

    conn.close()
    return users


def get_user_role(username):
    """Return the role of a user (admin/viewer)."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute(
        "SELECT role FROM users WHERE LOWER(username) = LOWER(?)",
        (username,)
    )
    result = cursor.fetchone()

    conn.close()
    return result[0] if result else None


def get_user_count():
    """Return total number of registered users."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM users")
    count = cursor.fetchone()[0]

    conn.close()
    return count


# ==========================
# USER CREATION
# ==========================

def user_exists(username):
    """Check if a username already exists."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM users WHERE username = ?", (username,))
    exists = cursor.fetchone()[0] > 0

    conn.close()
    return exists


def save_user_to_db(username, name, hashed_password, email=None):
    """
    Save a new user.
    First user becomes admin automatically.
    """
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM users")
        user_count = cursor.fetchone()[0]

        role = "admin" if user_count == 0 else "viewer"

        cursor.execute("""
            INSERT INTO users (username, name, password, email, role)
            VALUES (?, ?, ?, ?, ?)
        """, (username, name, hashed_password, email, role))

        conn.commit()
        conn.close()
        return True

    except sqlite3.IntegrityError:
        return False
    except Exception as e:
        st.error(f"Database error: {e}")
        return False


# ==========================
# PASSWORD MANAGEMENT
# ==========================

def update_password(username, new_password):
    """Update a user's password (hashed)."""
    try:
        hashed = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()

        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()

        cursor.execute(
            "UPDATE users SET password = ? WHERE LOWER(username) = LOWER(?)",
            (hashed, username)
        )

        updated = cursor.rowcount > 0
        conn.commit()
        conn.close()

        return updated

    except Exception as e:
        st.error(f"Error updating password: {e}")
        return False


def verify_user_email(username, email):
    """Check if username + email match."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute(
        "SELECT COUNT(*) FROM users WHERE LOWER(username)=LOWER(?) AND LOWER(email)=LOWER(?)",
        (username, email)
    )

    match = cursor.fetchone()[0] > 0
    conn.close()
    return match


# ==========================
# AUTHENTICATOR SETUP
# ==========================

def setup_authentication():
    """
    Prepare Streamlit-Authenticator with DB-backed credentials.
    Returns:
        authenticator, users_dict
    """
    init_users_db()
    users = load_users_from_db()

    credentials = {"usernames": users}

    authenticator = stauth.Authenticate(
        credentials,
        cookie_name="dksv_auth",
        key=SIGNATURE_KEY,
        cookie_expiry_days=30
    )

    return authenticator, users


# ==========================
# REGISTRATION UI
# ==========================

def register_user_ui():
    """Streamlit UI for registering a new user."""
    st.write("### 🆕 Register New User")

    with st.form("register_form", clear_on_submit=True):
        username = st.text_input("Username*", max_chars=20)
        name = st.text_input("Full Name*")
        email = st.text_input("Email*")
        pw1 = st.text_input("Password*", type="password")
        pw2 = st.text_input("Confirm Password*", type="password")

        submit = st.form_submit_button("Register")

        if submit:
            if not all([username, name, email, pw1, pw2]):
                st.error("Please fill all fields")
                return

            if pw1 != pw2:
                st.error("Passwords do not match")
                return

            if len(pw1) < 6:
                st.error("Password must be at least 6 characters")
                return

            if user_exists(username):
                st.error("Username already exists")
                return

            hashed = bcrypt.hashpw(pw1.encode(), bcrypt.gensalt()).decode()

            if save_user_to_db(username, name, hashed, email):
                if get_user_count() == 1:
                    st.success(f"Admin user '{username}' created!")
                else:
                    st.success(f"User '{username}' registered successfully!")

                st.balloons()
                st.rerun()
            else:
                st.error("Registration failed")


# ==========================
# PASSWORD RESET UI
# ==========================

def reset_password_ui():
    """Streamlit UI for resetting a password."""
    st.write("### 🔄 Reset Password")

    with st.form("reset_pw_form", clear_on_submit=True):
        username = st.text_input("Username*")
        email = st.text_input("Email*")
        pw1 = st.text_input("New Password*", type="password")
        pw2 = st.text_input("Confirm New Password*", type="password")

        submit = st.form_submit_button("Reset Password")

        if submit:
            if not all([username, email, pw1, pw2]):
                st.error("Please fill all fields")
                return

            if pw1 != pw2:
                st.error("Passwords do not match")
                return

            if not verify_user_email(username, email):
                st.error("Username and email do not match our records")
                return

            if update_password(username, pw1):
                st.success("Password updated successfully!")
                st.balloons()
            else:
                st.error("Password reset failed")
