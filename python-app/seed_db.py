#!/usr/bin/env python3
"""
Seed database with test data for IDOR and JWT exploitation demo.
Creates users with different roles and documents.
"""
import os
import sys
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Add current directory to path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

from app.models import Base, User, Document

def get_database_url():
    """Construct database URL from environment variables or use default."""
    # Check if DATABASE_URL is set directly
    database_url = os.getenv("DATABASE_URL")
    if database_url:
        return database_url
    
    # Build from individual components
    db_host = os.getenv("DB_HOST", "localhost")
    db_port = os.getenv("DB_PORT", "5432")
    db_name = os.getenv("DB_NAME", "mydb")
    db_user = os.getenv("DB_USER", "myuser")
    db_password = os.getenv("DB_PASSWORD", "mypassword")
    
    return f"postgresql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}"

def seed_database():
    """Create tables and populate with test data."""
    database_url = get_database_url()
    if not database_url:
        print("✗ Error: Database URL is not set", file=sys.stderr)
        sys.exit(1)
    
    # Safely extract database info for display (hide password)
    db_display = database_url.split('@')[1] if database_url and '@' in database_url else '***'
    print(f"Connecting to database: {db_display}")
    
    engine = create_engine(database_url)
    
    # Create tables
    print("Creating tables...")
    Base.metadata.create_all(engine)
    
    Session = sessionmaker(bind=engine)
    session = Session()
    
    try:
        # Clear existing data (for idempotency)
        print("Clearing existing data...")
        session.query(Document).delete()
        session.query(User).delete()
        session.commit()
        
        # Create test users
        print("Creating test users...")
        users_data = [
            {"username": "alice", "role": "user"},
            {"username": "bob", "role": "user"},
            {"username": "charlie", "role": "user"},
            {"username": "admin", "role": "admin"},
            {"username": "victim", "role": "user"},
        ]
        
        users = []
        for user_data in users_data:
            user = User(**user_data)
            session.add(user)
            users.append(user)
        
        session.flush()  # Get IDs
        
        # Create documents for users
        print("Creating documents...")
        documents_data = [
            {"user_id": users[0].id, "filename": "alice_passport.pdf"},
            {"user_id": users[0].id, "filename": "alice_contract.pdf"},
            {"user_id": users[1].id, "filename": "bob_id_card.pdf"},
            {"user_id": users[1].id, "filename": "bob_bank_statement.pdf"},
            {"user_id": users[1].id, "filename": "bob_medical_record.pdf"},
            {"user_id": users[2].id, "filename": "charlie_diploma.pdf"},
            {"user_id": users[4].id, "filename": "victim_secret_document.pdf"},
            {"user_id": users[4].id, "filename": "victim_private_info.pdf"},
        ]
        
        for doc_data in documents_data:
            document = Document(**doc_data)
            session.add(document)
        
        session.commit()
        print("✓ Database seeded successfully!")
        print("\nTest users created:")
        for user in users:
            doc_count = len([d for d in documents_data if d["user_id"] == user.id])
            print(f"  - {user.username} (id={user.id}, role={user.role}) - {doc_count} documents")
        
    except Exception as e:
        session.rollback()
        print(f"✗ Error seeding database: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        session.close()

if __name__ == "__main__":
    seed_database()