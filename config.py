import os

EXPECTED_PER_MEMBER = 1000 / 120.0

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://neondb_owner:npg_8YCW2OiTJcSM@ep-solitary-dream-agcfo4v4-pooler.c-2.eu-central-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require")

# Fallback to SQLite when running locally 
if not DATABASE_URL: 
    DATABASE_URL = "sqlite:///local.db" 
