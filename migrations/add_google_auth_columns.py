import mysql.connector

def add_google_auth_columns():
    try:
        # Connect to MySQL database
        conn = mysql.connector.connect(
            host="127.0.0.1",
            user="root",
            password="yui1987",
            database="trading_website"
        )
        
        cursor = conn.cursor()
        
        # Add google_id column if it doesn't exist
        cursor.execute("""
            SELECT COUNT(*)
            FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA = 'trading_website' 
            AND TABLE_NAME = 'users' 
            AND COLUMN_NAME = 'google_id'
        """)
        
        if cursor.fetchone()[0] == 0:
            cursor.execute("""
                ALTER TABLE users 
                ADD COLUMN google_id VARCHAR(100) UNIQUE
            """)
            print("Added google_id column to users table")
        
        # Add email column if it doesn't exist
        cursor.execute("""
            SELECT COUNT(*)
            FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA = 'trading_website' 
            AND TABLE_NAME = 'users' 
            AND COLUMN_NAME = 'email'
        """)
        
        if cursor.fetchone()[0] == 0:
            cursor.execute("""
                ALTER TABLE users 
                ADD COLUMN email VARCHAR(255) UNIQUE
            """)
            print("Added email column to users table")
        
        # Commit changes and close connection
        conn.commit()
        cursor.close()
        conn.close()
        
        print("Database schema updated successfully!")
        
    except Exception as e:
        print(f"Error updating database schema: {str(e)}")

if __name__ == "__main__":
    add_google_auth_columns()
