import express, { Request, Response, NextFunction } from 'express';
import fs from 'fs';
import path from 'path';
import session from 'express-session';
import cookieParser from 'cookie-parser';
import multer from 'multer';
import { format } from 'date-fns';

interface User {
  username: string;
  password: string;
}

// Extend Express Request type to include session
declare module 'express-session' {
  interface SessionData {
    user?: string;
  }
}

const app = express();
const port = 3000;

// Configure middleware
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 3600000 } // 1 hour
}));

function getUsers(): User[] {
  try {
    const configUsersPath = process.env.CONFIG_USERS || path.join(__dirname, '..', 'config', 'users.txt');
    const fileContent = fs.readFileSync(configUsersPath, 'utf-8');
    const lines = fileContent.split('\n').filter(line => line.trim() !== '');
    
    return lines.map(line => {
      const [username, password] = line.split(':');
      return { username, password };
    });
  } catch (error) {
    console.error('Error reading users file:', error);
    return [];
  }
}

const USERS = getUsers();

// Authentication middleware
const authenticate = (req: Request, res: Response, next: NextFunction): void => {
  // If user is already logged in via session
  if (req.session.user) {
    return next();
  }

  // Get auth header for basic auth
  const authHeader = req.headers.authorization;
  
  if (!authHeader) {
    res.setHeader('WWW-Authenticate', 'Basic');
    res.status(401).send('Authentication required');
    return;
  }
  
  // Parse credentials
  const auth = Buffer.from(authHeader.split(' ')[1], 'base64').toString().split(':');
  const username = auth[0];
  const password = auth[1];
  
  // Check credentials
  const user = USERS.find(user => user.username === username && user.password === password);
  
  if (!user) {
    res.setHeader('WWW-Authenticate', 'Basic');
    res.status(401).send('Invalid credentials');
    return;
  }
  
  // Set user in session
  req.session.user = username;
  next();
};

app.get('/login', (req: Request, res: Response) => {
  res.send(`<!DOCTYPE html>
<html>
<head>
  <title>Login</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.classless.min.css">
</head>
<body>
  <main class="container">
    <h1>Login</h1>
    <form action="/login" method="POST">
      <div>
        <label for="username">Username:</label>
        <input type="text" id="username" name="username" required>
      </div>
      <div>
        <label for="password">Password:</label>
        <input type="password" id="password" name="password" required>
      </div>
      <button type="submit">Login</button>
    </form>
    <p><a href="/">Back to Home</a></p>
  </main>
</body>
</html>`);
});

app.post('/login', (req: Request, res: Response) => {
  const { username, password } = req.body;
  
  const user = USERS.find(user => user.username === username && user.password === password);
  
  if (user) {
    req.session.user = username;
    res.redirect('/');
  } else {
    res.send(`<!DOCTYPE html>
<html>
<head>
  <title>Login Failed</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.classless.min.css">
</head>
<body>
  <main class="container">
    <h1>Login Failed</h1>
    <p>Invalid username or password.</p>
    <p><a href="/login">Try Again</a></p>
    <p><a href="/">Back to Home</a></p>
  </main>
</body>
</html>`);
  }
});

app.get('/logout', (req: Request, res: Response) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Error destroying session:', err);
    }
    res.redirect('/');
  });
});

app.get('/users', (req: Request, res: Response) => {
  try {
    const usernames = USERS.map(user => user.username);
    
    res.setHeader('Content-Type', 'text/plain');
    res.send(usernames.join('\n'));
  } catch (error) {
    console.error('Error processing users:', error);
    res.status(500).json({ error: 'Failed to process users' });
  }
});

// File upload configuration
const MAX_FILE_SIZE = 65536; // 64KB
const ALLOWED_EXTENSIONS = ['.c', '.cpp', '.py'];

// Configure multer for file upload
const memoryStorage = multer.memoryStorage();
const upload = multer({
  storage: memoryStorage,
  limits: {
    fileSize: MAX_FILE_SIZE
  },
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (ALLOWED_EXTENSIONS.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error(`Only ${ALLOWED_EXTENSIONS.join(', ')} files are allowed`));
    }
  }
});

// Create upload form route
app.get('/upload', authenticate, (req: Request, res: Response) => {
  res.send(`<!DOCTYPE html>
<html>
<head>
  <title>Upload File</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.classless.min.css">
</head>
<body>
  <main class="container">
    <h1>Upload File</h1>
    <p>Maximum size: 64KB. Allowed extensions: ${ALLOWED_EXTENSIONS.join(', ')}</p>
    <form action="/upload" method="POST" enctype="multipart/form-data">
      <div>
        <label for="file">Choose a file:</label>
        <input type="file" id="file" name="file" required>
      </div>
      <button type="submit">Upload</button>
    </form>
    <p><a href="/">Back to Home</a></p>
  </main>
</body>
</html>`);
});

// Handle file upload
app.post('/upload', authenticate, (req: Request, res: Response, next: NextFunction) => {
  upload.single('file')(req, res, (err) => {
    if (err instanceof multer.MulterError) {
      if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).send('File too large. Maximum size is 64KB.');
      }
      return res.status(400).send(err.message);
    } else if (err) {
      return res.status(400).send(err.message);
    }

    // Continue with the request
    try {
      // Validate that a file was uploaded
      if (!req.file) {
        return res.status(400).send('No file uploaded');
      }

      const username = req.session.user!;
      const outputDir = process.env.OUTPUT_DIR || 'uploads';
      const timestamp = format(new Date(), 'yyyy-MM-dd-HHmmss');
      const userDir = path.join(outputDir, username);
      const timestampDir = path.join(userDir, timestamp);
      const filename = req.file.originalname;
      
      // Create directories if they don't exist
      if (!fs.existsSync(outputDir)) {
        fs.mkdirSync(outputDir, { recursive: true });
      }
      if (!fs.existsSync(userDir)) {
        fs.mkdirSync(userDir, { recursive: true });
      }
      if (!fs.existsSync(timestampDir)) {
        fs.mkdirSync(timestampDir, { recursive: true });
      }
      
      // Save the file
      const filePath = path.join(timestampDir, filename);
      fs.writeFileSync(filePath, req.file.buffer);
      
      // Success page
      res.send(`<!DOCTYPE html>
<html>
<head>
  <title>Upload Success</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.classless.min.css">
</head>
<body>
  <main class="container">
    <h1>Upload Successful</h1>
    <p>File <strong>${filename}</strong> uploaded successfully.</p>
    <p>Saved to: ${filePath}</p>
    <p><a href="/upload">Upload Another File</a></p>
    <p><a href="/">Back to Home</a></p>
  </main>
</body>
</html>`);
    } catch (error) {
      console.error('Error in file upload:', error);
      res.status(500).send('Error uploading file');
    }
  });
});

// Home page handler
app.get('/', (req: Request, res: Response) => {
  const loggedIn = !!req.session.user;
  const username = req.session.user || '';
  
  let html = `<!DOCTYPE html>
<html>
<head>
  <title>Home Page</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.classless.min.css">
</head>
<body>
  <main class="container">
    <h1>Welcome</h1>
    <div>`;
  
  if (loggedIn) {
    html += `<p>Logged in as: ${username} <a href="/logout" role="button">Logout</a></p>`;
  } else {
    html += `<p>Not logged in. <a href="/login" role="button">Login</a></p>`;
  }
  
  html += `</div>
    <ul>
      <li><a href="/users">View Users</a></li>`;
  
  if (loggedIn) {
    html += `\n      <li><a href="/upload">Upload File</a></li>`;
  }
  
  html += `
    </ul>
  </main>
</body>
</html>`;
  
  res.send(html);
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
  console.log(`CONFIG_USERS: ${process.env.CONFIG_USERS || 'using default path'}`);
  console.log(`OUTPUT_DIR: ${process.env.OUTPUT_DIR || 'uploads'}`);
});