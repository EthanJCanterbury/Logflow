
import os
from main import app, db
from sqlalchemy import text

# Initialize the app context
with app.app_context():
    # Add storage_size column if it doesn't exist
    try:
        db.session.execute(text('ALTER TABLE project ADD COLUMN IF NOT EXISTS storage_size BIGINT DEFAULT 0'))
        db.session.commit()
        print("Added storage_size column to project table")
    except Exception as e:
        print(f"Error adding column (might already exist): {e}")
    
    print("Migration completed successfully")
