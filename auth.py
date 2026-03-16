"""
Authentication module for Streamlit app
PostgreSQL-backed authentication
"""
 
import bcrypt 
import streamlit as st
import streamlit_authenticator as stauth
from sqlalchemy import text
from database import engine


SIGNATURE_KEY = "simple_auth_key_12345"


# =========================================================
# USER RETRIEVAL
# =========================================================

def load_users_from_db():
    """
    Load all users for streamlit-authenticator.
    Returns:
        dict: {username: {name, password, email, role}}
    """

    with engine.connect() as conn:
        rows = conn.execute(text("""
            SELECT username, name, password, email, role
            FROM users
        """)).fetchall()

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
    with engine.connect() as conn:
        rows = conn.execute(text("""
            SELECT username, name, role
            FROM users
            ORDER BY created_at DESC
        """)).fetchall()

    return rows

def init_users_table():
    with engine.begin() as conn:
        conn.execute(text("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            role TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """))


def get_user_role(username):
    with engine.connect() as conn:
        result = conn.execute(
            text("""
                SELECT role
                FROM users
                WHERE LOWER(username)=LOWER(:username)
            """),
            {"username": username}
        ).fetchone()

    return result[0] if result else None


def get_user_count():
    with engine.connect() as conn:
        count = conn.execute(text("""
            SELECT COUNT(*)
            FROM users
        """)).scalar()

    return count


# =========================================================
# USER MANAGEMENT
# =========================================================

def user_exists(username):
    with engine.connect() as conn:
        exists = conn.execute(
            text("""
                SELECT COUNT(*)
                FROM users
                WHERE username=:username
            """),
            {"username": username}
        ).scalar()

    return exists > 0


def save_user_to_db(username, name, hashed_password, email=None):

    try:

        with engine.begin() as conn:

            user_count = conn.execute(
                text("SELECT COUNT(*) FROM users")
            ).scalar()

            role = "admin" if user_count == 0 else "viewer"

            conn.execute(text("""
                INSERT INTO users
                (username, name, password, email, role)
                VALUES (:username, :name, :password, :email, :role)
            """), {
                "username": username,
                "name": name,
                "password": hashed_password,
                "email": email,
                "role": role
            })

        return True

    except Exception as e:
        st.error(f"Database error: {e}")
        return False


# =========================================================
# PASSWORD MANAGEMENT
# =========================================================

def update_password(username, new_password):

    hashed = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()

    with engine.begin() as conn:

        result = conn.execute(text("""
            UPDATE users
            SET password=:password
            WHERE LOWER(username)=LOWER(:username)
        """), {
            "password": hashed,
            "username": username
        })

    return result.rowcount > 0


def verify_user_email(username, email):

    with engine.connect() as conn:

        match = conn.execute(text("""
            SELECT COUNT(*)
            FROM users
            WHERE LOWER(username)=LOWER(:username)
            AND LOWER(email)=LOWER(:email)
        """), {
            "username": username,
            "email": email
        }).scalar()

    return match > 0


# =========================================================
# AUTHENTICATOR SETUP
# =========================================================

def setup_authentication():

    init_users_table()

    users = load_users_from_db()

    credentials = {"usernames": users}

    authenticator = stauth.Authenticate(
        credentials,
        cookie_name="dksv_auth",
        key=SIGNATURE_KEY,
        cookie_expiry_days=30
    )

    return authenticator, users


# =========================================================
# REGISTRATION UI
# =========================================================

def register_user_ui():

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
                    st.success(f"User '{username}' registered!")

                st.balloons()
                st.rerun()
