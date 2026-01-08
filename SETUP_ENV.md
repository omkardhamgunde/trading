# Environment Variables Setup Guide

## Quick Start

1. **Install python-dotenv** (if not already installed):
   ```bash
   pip install python-dotenv
   ```

2. **Create a `.env` file** in the project root directory:
   ```bash
   cp .env.example .env
   ```

3. **Edit the `.env` file** with your actual credentials:
   ```env
   # Flask Configuration
   SECRET_KEY=your-generated-secret-key-here
   FLASK_ENV=development
   SESSION_COOKIE_SECURE=False

   # Google OAuth 2.0 Configuration
   GOOGLE_CLIENT_ID=your-google-client-id-here
   GOOGLE_CLIENT_SECRET=your-google-client-secret-here
   GOOGLE_REDIRECT_URI=http://127.0.0.1:5001/login/google/authorized

   # OAuth Development Setting
   OAUTHLIB_INSECURE_TRANSPORT=1

   # MySQL Database Configuration
   MYSQL_HOST=127.0.0.1
   MYSQL_USER=root
   MYSQL_PASSWORD=your-database-password-here
   MYSQL_DB=trading_website
   ```

4. **Generate a secure SECRET_KEY**:
   ```python
   import secrets
   print(secrets.token_hex(16))
   ```
   Copy the output and paste it as your `SECRET_KEY` value.

5. **Run the application**:
   ```bash
   python app.py
   ```

## Important Notes

- ✅ The `.env` file is already in `.gitignore` - it will NOT be committed to Git
- ✅ Never share your `.env` file or commit it to version control
- ✅ The `.env.example` file is a template that can be safely committed
- ✅ For production, set `SESSION_COOKIE_SECURE=True` and `OAUTHLIB_INSECURE_TRANSPORT=0`

## Getting Google OAuth Credentials

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the Google+ API
4. Go to "Credentials" → "Create Credentials" → "OAuth 2.0 Client ID"
5. Configure the consent screen
6. Add authorized redirect URI: `http://127.0.0.1:5001/login/google/authorized`
7. Copy the Client ID and Client Secret to your `.env` file

## Security Best Practices

- 🔒 Use strong, unique passwords for database
- 🔒 Generate a random SECRET_KEY (use `secrets.token_hex(32)` for production)
- 🔒 Never commit `.env` to version control
- 🔒 Use different credentials for development and production
- 🔒 Rotate credentials regularly
- 🔒 Use environment variables in production (not `.env` files)
