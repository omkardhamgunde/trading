from app import app, mysql

def init_security_table():
    """Create the login_history table for the Security Dashboard."""
    with app.app_context():
        cursor = mysql.connection.cursor()
        
        # Create table if it doesn't exist
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS login_history (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NULL,
            username VARCHAR(100),
            ip_address VARCHAR(45),
            user_agent TEXT,
            status VARCHAR(20),
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        mysql.connection.commit()
        print("✅ Security table `login_history` initialized securely.")

if __name__ == '__main__':
    init_security_table()
