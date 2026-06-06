from app import app, mysql
from werkzeug.security import generate_password_hash
import sys

def migrate_passwords():
    """Migrate all plain text passwords in the database to werkzeug pbkdf2:sha256 hashes."""
    with app.app_context():
        # Connect to DB
        cursor = mysql.connection.cursor()
        
        # Get all users who have passwords that are NOT already hashed
        cursor.execute("SELECT id, username, password FROM users WHERE password IS NOT NULL AND password != '' AND password NOT LIKE 'scrypt:%' AND password NOT LIKE 'pbkdf2:%'")
        users = cursor.fetchall()
        
        if not users:
            print("✅ No plain text passwords found to migrate. Everything is secure!")
            return
            
        print(f"🔒 Found {len(users)} users with plain text passwords. Securing them now...")
        
        for user in users:
            user_id = user[0]
            username = user[1]
            plain_password = user[2]
            
            # Generate strong hash
            secure_hash = generate_password_hash(plain_password)
            
            # Update DB
            cursor.execute("UPDATE users SET password = %s WHERE id = %s", (secure_hash, user_id))
            print(f"  -> Secured password for user: {username}")
            
        mysql.connection.commit()
        print("✅ Migration complete! All passwords are now cryptographically hashed.")

if __name__ == '__main__':
    try:
        migrate_passwords()
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        sys.exit(1)
