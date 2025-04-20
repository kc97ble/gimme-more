# Gimme More

A simple Node.js server for user authentication and file uploads.

## Features

- User authentication (login/logout)
- List available users
- File uploads with size and extension validation
- Clean file organization by username and timestamp

## Installation

1. Clone the repository
2. Install dependencies:
   ```
   npm install
   ```
3. Create a `.env` file based on `.env.example`:
   ```
   cp .env.example .env
   ```
4. Edit the `.env` file with your configuration
5. Build the TypeScript code:
   ```
   npm run build
   ```

## Configuration

The application requires the following environment variables:

- `CONFIG_USERS`: Path to the users configuration file (format: username:password)
- `OUTPUT_DIR`: Directory where uploaded files will be stored
- `SESSION_SECRET`: Secret key for session encryption (at least 8 characters)
- `PORT`: Port number for the server

These can be set in the `.env` file or directly as environment variables.

## Running the server

For development:
```
npm run dev
```

For production:
```
npm start
```

## User Management

Users are defined in a plain text file with each line containing `username:password`.

## File Uploads

- Only accepts files with `.c`, `.cpp`, or `.py` extensions
- Maximum file size: 64KB
- Files are saved to: `<OUTPUT_DIR>/<username>/<timestamp>/<filename>`