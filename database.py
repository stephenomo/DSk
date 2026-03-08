# database.py
from sqlalchemy import create_engine, text
import pandas as pd
from config import DATABASE_URL

# Create global engine
engine = create_engine(DATABASE_URL, pool_pre_ping=True)


# ==========================
# INITIALIZE DATABASE
# ==========================
def init_db():
    with engine.begin() as conn:
        # Monthly contributions
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS contributions (
                id SERIAL PRIMARY KEY,
                member TEXT,
                amount DOUBLE PRECISION,
                month TEXT,
                date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """))

        # Special projects
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS special_projects (
                id SERIAL PRIMARY KEY,
                project_name TEXT,
                description TEXT,
                target_amount DOUBLE PRECISION,
                deadline TEXT,
                status TEXT DEFAULT 'active',
                document BYTEA
            )
        """))

        # Special contributions
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS special_contributions (
                id SERIAL PRIMARY KEY,
                project_id INTEGER REFERENCES special_projects(id) ON DELETE CASCADE,
                name TEXT,
                amount DOUBLE PRECISION,
                notes TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """))

        # Project income
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS project_income (
                id SERIAL PRIMARY KEY,
                project_id INTEGER REFERENCES special_projects(id) ON DELETE CASCADE,
                source TEXT,
                amount DOUBLE PRECISION,
                notes TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """))

        # Deletion logs
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS deletion_logs (
                id SERIAL PRIMARY KEY,
                record_type TEXT,
                record_id INTEGER,
                deleted_by TEXT,
                reason TEXT,
                deleted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """))


# ==========================
# MONTHLY CONTRIBUTIONS
# ==========================
def add_contribution(member, amount, month):
    with engine.begin() as conn:
        conn.execute(
            text("""
                INSERT INTO contributions (member, amount, month)
                VALUES (:member, :amount, :month)
            """),
            {"member": member, "amount": float(amount), "month": month},
        )


def get_all_contributions():
    with engine.connect() as conn:
        df = pd.read_sql(
            text("""
                SELECT id, member, amount, month, date
                FROM contributions
                ORDER BY date DESC
            """),
            conn,
        )
    return df


def delete_contribution_with_reason(entry_id, deleted_by, reason):
    entry_id = int(entry_id)  # FIX

    with engine.begin() as conn:
        conn.execute(
            text("""
                INSERT INTO deletion_logs (record_type, record_id, deleted_by, reason)
                VALUES ('contribution', :id, :user, :reason)
            """),
            {"id": entry_id, "user": deleted_by, "reason": reason},
        )
        conn.execute(
            text("DELETE FROM contributions WHERE id = :id"),
            {"id": entry_id},
        )


# ==========================
# SPECIAL PROJECTS
# ==========================
def create_special_project(name, desc, target, deadline, doc):
    document_bytes = doc.read() if doc else None
    with engine.begin() as conn:
        result = conn.execute(
            text("""
                INSERT INTO special_projects (project_name, description, target_amount, deadline, document)
                VALUES (:name, :desc, :target, :deadline, :document)
                RETURNING id
            """),
            {
                "name": name,
                "desc": desc,
                "target": float(target),
                "deadline": deadline,
                "document": document_bytes,
            },
        )
        project_id = result.scalar()
    return project_id


def get_all_special_projects():
    with engine.connect() as conn:
        df = pd.read_sql(
            text("SELECT * FROM special_projects ORDER BY id DESC"),
            conn,
        )
    return df


# ==========================
# SPECIAL CONTRIBUTIONS
# ==========================
def add_special_project_contribution(project_id, name, amount, notes):
    with engine.begin() as conn:
        conn.execute(
            text("""
                INSERT INTO special_contributions (project_id, name, amount, notes)
                VALUES (:pid, :name, :amount, :notes)
            """),
            {
                "pid": project_id,
                "name": name,
                "amount": float(amount),
                "notes": notes,
            },
        )


def get_special_project_contributions(project_id):
    with engine.connect() as conn:
        df = pd.read_sql(
            text("""
                SELECT id, name, amount, notes, created_at
                FROM special_contributions
                WHERE project_id = :pid
                ORDER BY created_at DESC
            """),
            conn,
            params={"pid": project_id},
        )
    return df


def delete_special_contribution_with_reason(contrib_id, deleted_by, reason):
    contrib_id = int(contrib_id)  # FIX

    with engine.begin() as conn:
        conn.execute(
            text("""
                INSERT INTO deletion_logs (record_type, record_id, deleted_by, reason)
                VALUES ('special_contribution', :id, :user, :reason)
            """),
            {"id": contrib_id, "user": deleted_by, "reason": reason},
        )
        conn.execute(
            text("DELETE FROM special_contributions WHERE id = :id"),
            {"id": contrib_id},
        )



# ==========================
# PROJECT INCOME
# ==========================
def add_project_income(project_id, source, amount, notes):
    with engine.begin() as conn:
        conn.execute(
            text("""
                INSERT INTO project_income (project_id, source, amount, notes)
                VALUES (:pid, :source, :amount, :notes)
            """),
            {
                "pid": project_id,
                "source": source,
                "amount": float(amount),
                "notes": notes,
            },
        )


def get_project_income(project_id):
    with engine.connect() as conn:
        df = pd.read_sql(
            text("""
                SELECT id, source, amount, notes, created_at
                FROM project_income
                WHERE project_id = :pid
                ORDER BY created_at DESC
            """),
            conn,
            params={"pid": project_id},
        )
    return df


def delete_project_income_with_reason(income_id, deleted_by, reason):
    income_id = int(income_id)  # FIX

    with engine.begin() as conn:
        conn.execute(
            text("""
                INSERT INTO deletion_logs (record_type, record_id, deleted_by, reason)
                VALUES ('project_income', :id, :user, :reason)
            """),
            {"id": income_id, "user": deleted_by, "reason": reason},
        )
        conn.execute(
            text("DELETE FROM project_income WHERE id = :id"),
            {"id": income_id},
        )



# ==========================
# FINANCIAL SUMMARY
# ==========================
def get_project_financial_summary(project_id):
    with engine.connect() as conn:
        contrib = conn.execute(
            text("SELECT COALESCE(SUM(amount), 0) FROM special_contributions WHERE project_id = :pid"),
            {"pid": project_id},
        ).scalar() or 0.0

        income = conn.execute(
            text("SELECT COALESCE(SUM(amount), 0) FROM project_income WHERE project_id = :pid"),
            {"pid": project_id},
        ).scalar() or 0.0

    return {
        "contributions": float(contrib),
        "income": float(income),
        "total": float(contrib) + float(income),
    }
