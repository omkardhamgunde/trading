-- Add google_id and email columns to users table if they don't exist
ALTER TABLE users
ADD COLUMN IF NOT EXISTS google_id VARCHAR(100) UNIQUE,
ADD COLUMN IF NOT EXISTS email VARCHAR(255) UNIQUE;
