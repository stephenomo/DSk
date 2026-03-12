# app.py
import streamlit as st
import pandas as pd
import plotly.express as px

from config import EXPECTED_PER_MEMBER
from auth import (
    setup_authentication,
    register_user_ui,
    get_user_role,
)
from database import (
    init_db,
    get_all_contributions,
    add_contribution,
    delete_contribution_with_reason,
    create_special_project,
    get_all_special_projects,
    add_special_project_contribution,
    get_special_project_contributions,
    delete_special_contribution_with_reason,
    add_project_income,
    get_project_income,
    delete_project_income_with_reason,
    get_project_financial_summary,
)

DIVISOR = 120

st.set_page_config(page_title="💰 DKSV TEAM", layout="wide")

# =========================================================
# AUTHENTICATION SETUP
# =========================================================

authenticator, users = setup_authentication()

# First-time setup: no users exist → show registration only
if len(users) == 0:
    st.title("💰 DKSV TEAM")
    st.info("No users found. Please create the first admin account.")
    register_user_ui()
    st.stop()

# Try login safely
try:
    authenticator.login(location="main")
except Exception:
    st.error("Authentication system error. Please reload the page.")
    st.stop()

authentication_status = st.session_state.get("authentication_status")
username = st.session_state.get("username")
name = st.session_state.get("name")

# =========================================================
# LOGIN GATE
# =========================================================

if authentication_status is None:
    st.title("💰 DKSV TEAM")
    st.info("🔐 Please log in to continue.")
    st.stop()

if authentication_status is False:
    st.title("💰 DKSV TEAM")
    st.error("❌ Incorrect username or password")
    st.stop()

# User is authenticated
user_role = get_user_role(username) or "viewer"

# =========================================================
# HEADER & ACCOUNT INFO
# =========================================================

c1, c2 = st.columns([8, 1])
with c1:
    st.title("💰 DKSV TEAM")
    st.markdown(
        """
        <p style='font-size: 1.2em; color: #4CAF50; font-weight: 500; margin-top: -10px;'>
            🤝 <i>Together We Grow, Together We Prosper</i> ✨
        </p>
        """,
        unsafe_allow_html=True,
    )
with c2:
    with st.popover("⚙️"):
        st.write("### Account Info")
        st.write(f"**Name:** {name}")
        st.write(f"**Username:** {username}")
        st.write(f"**Role:** {user_role.upper()}")
        st.divider()

        # SAFE LOGOUT — only shown when logged in
        if authentication_status:
            authenticator.logout("🚪 Logout", "main")

st.divider()

# =========================================================
# INIT DB & LOAD DATA
# =========================================================

init_db()
df = get_all_contributions()

main_tab, projects_tab = st.tabs(["📊 Monthly Contributions", "🎯 Special Projects"])

# =========================================================
# SIDEBAR (ADMIN ONLY)
# =========================================================

with st.sidebar:
    if user_role == "admin":
        st.header("🛠️ Admin Controls")

        # Admin-only registration
        st.subheader("🆕 Register New User")
        register_user_ui()

        st.divider()

        # Add contribution
        st.subheader("➕ Add Contribution")
        with st.form("add_contribution_form"):
            member_name = st.text_input("Member Name*")
            amount_raw = st.number_input("Amount*", min_value=0.0, format="%.2f")
            month = st.text_input("Month* (e.g., January 2025)")
            if st.form_submit_button("Add"):
                if not member_name or not month or amount_raw <= 0:
                    st.error("Please fill all fields")
                else:
                    amount = round(amount_raw / DIVISOR, 2)
                    add_contribution(member_name, amount, month)
                    st.success("Contribution added.")
                    st.rerun()

        # Delete contribution
        st.subheader("🗑️ Delete Contribution")
        if not df.empty:
            df_del = df.copy()
            df_del["label"] = df_del.apply(
                lambda r: f"{r['member']} | {r['month']} | ${r['amount']:.2f}", axis=1
            )
            selected = st.selectbox("Select entry:", df_del["label"])
            reason = st.text_area("Reason for deletion (required)")
            if st.button("Delete Entry", type="primary"):
                if not reason.strip():
                    st.error("Please provide a reason.")
                else:
                    entry_id = int(df_del.loc[df_del["label"] == selected, "id"].iloc[0])
                    delete_contribution_with_reason(entry_id, username, reason)
                    st.success("Entry deleted and logged.")
                    st.rerun()
        else:
            st.info("No entries to delete.")

    else:
        st.info("One Step At a Time")

# =========================================================
# MAIN TAB — MONTHLY CONTRIBUTIONS
# =========================================================

with main_tab:
    st.header("📊 Monthly Contributions")

    if df.empty:
        st.info("No contributions recorded yet.")
    else:
        # Metrics
        c1, c2, c3 = st.columns(3)
        c1.metric("Total Collected", f"${df['amount'].sum():,.2f}")
        c2.metric("Contributors", df["member"].nunique())
        c3.metric("Entries", len(df))

        st.divider()

        # Expected per month check
        st.subheader("📅 Monthly Expected Contribution Check")
        monthly_group = df.groupby(["month", "member"], as_index=False)["amount"].sum()

        warnings = []
        for _, row in monthly_group.iterrows():
            if row["amount"] < EXPECTED_PER_MEMBER:
                warnings.append(
                    f"{row['member']} contributed ${row['amount']:.2f} in {row['month']} "
                    f"(expected ${EXPECTED_PER_MEMBER:.2f})"
                )

        if warnings:
            st.warning("⚠️ Members below expected monthly contribution:")
            for w in warnings:
                st.write(f"- {w}")
        else:
            st.success("All members met expected monthly contributions.")

        st.divider()

        # Recent contributions
        st.subheader("Recent Contributions")
        st.dataframe(df.sort_values("date", ascending=False), use_container_width=True)

        st.divider()

        # Chart by member
        st.subheader("📈 Total by Member")
        by_member = df.groupby("member", as_index=False)["amount"].sum()
        fig = px.bar(
            by_member,
            x="member",
            y="amount",
            title="Total Contributed per Member",
            color="amount",
            color_continuous_scale="Blues",
        )
        st.plotly_chart(fig, use_container_width=True)

# =========================================================
# SPECIAL PROJECTS TAB
# =========================================================

with projects_tab:
    st.header("🎯 Special Projects")

    # Create project
    if user_role == "admin":
        with st.expander("➕ Create New Special Project"):
            with st.form("create_project_form"):
                proj_name = st.text_input("Project Name*")
                proj_desc = st.text_area("Description")
                proj_target_raw = st.number_input("Target Amount*", min_value=0.0)
                proj_deadline = st.date_input("Deadline (optional)")
                proj_doc = st.file_uploader("Upload Document (optional)")

                if st.form_submit_button("Create Project"):
                    if not proj_name or proj_target_raw <= 0:
                        st.error("Please fill required fields.")
                    else:
                        proj_target = round(proj_target_raw / DIVISOR, 2)
                        deadline_str = proj_deadline.isoformat() if proj_deadline else None
                        create_special_project(proj_name, proj_desc, proj_target, deadline_str, proj_doc)
                        st.success("Project created.")
                        st.rerun()

    # List projects
    projects_df = get_all_special_projects()
    if projects_df.empty:
        st.info("No special projects yet.")
    else:
        for _, project in projects_df.iterrows():
            st.divider()
            st.subheader(f"📌 {project['project_name']}")
            if project["description"]:
                st.write(project["description"])

            summary = get_project_financial_summary(project["id"])
            c1, c2, c3 = st.columns(3)
            c1.metric("Contributions", f"${summary['contributions']:,.2f}")
            c2.metric("Income", f"${summary['income']:,.2f}")
            c3.metric("Total", f"${summary['total']:,.2f}")

            # Add special contribution
            if user_role == "admin":
                with st.expander("➕ Add Special Contribution"):
                    with st.form(f"add_contrib_{project['id']}"):
                        contrib_name = st.text_input("Contributor Name")
                        amount_raw = st.number_input("Amount", min_value=0.0)
                        notes = st.text_area("Notes")
                        if st.form_submit_button("Add"):
                            amount = round(amount_raw / DIVISOR, 2)
                            add_special_project_contribution(project["id"], contrib_name, amount, notes)
                            st.success("Contribution added.")
                            st.rerun()

            # Show contributions
            contrib_df = get_special_project_contributions(project["id"])
            st.subheader("📋 Contributions")
            st.dataframe(contrib_df, use_container_width=True)

            if user_role == "admin" and not contrib_df.empty:
                contrib_df["label"] = contrib_df.apply(
                    lambda r: f"{r['name']} | ${r['amount']:.2f}", axis=1
                )
                selected = st.selectbox(
                    "Select contribution to delete:",
                    contrib_df["label"],
                    key=f"sel_contrib_{project['id']}",
                )
                reason = st.text_area(
                    "Reason for deletion (required)",
                    key=f"reason_contrib_{project['id']}",
                )
                if st.button(
                    "Delete Contribution",
                    key=f"btn_del_contrib_{project['id']}",
                    type="primary",
                ):
                    if not reason.strip():
                        st.error("Please provide a reason.")
                    else:
                        contrib_id = int(
                            contrib_df.loc[contrib_df["label"] == selected, "id"].iloc[0]
                        )
                        delete_special_contribution_with_reason(contrib_id, username, reason)
                        st.success("Contribution deleted and logged.")
                        st.rerun()

            # Add income
            if user_role == "admin":
                with st.expander("➕ Add Project Income"):
                    with st.form(f"add_income_{project['id']}"):
                        source = st.text_input("Income Source")
                        amount_raw = st.number_input("Amount", min_value=0.0)
                        notes = st.text_area("Notes")
                        if st.form_submit_button("Add Income"):
                            amount = round(amount_raw / DIVISOR, 2)
                            add_project_income(project["id"], source, amount, notes)
                            st.success("Income added.")
                            st.rerun()

            # Show income
            income_df = get_project_income(project["id"])
            st.subheader("📋 Income")
            st.dataframe(income_df, use_container_width=True)

            if user_role == "admin" and not income_df.empty:
                income_df["label"] = income_df.apply(
                    lambda r: f"{r['source']} | ${r['amount']:.2f}", axis=1
                )
                selected = st.selectbox(
                    "Select income to delete:",
                    income_df["label"],
                    key=f"sel_income_{project['id']}",
                )
                reason = st.text_area(
                    "Reason for deletion (required)",
                    key=f"reason_income_{project['id']}",
                )
                if st.button(
                    "Delete Income",
                    key=f"btn_del_income_{project['id']}",
                    type="primary",
                ):
                    if not reason.strip():
                        st.error("Please provide a reason.")
                    else:
                        income_id = int(
                            income_df.loc[income_df["label"] == selected, "id"].iloc[0]
                        )
                        delete_project_income_with_reason(income_id, username, reason)
                        st.success("Income deleted and logged.")
                        st.rerun()
