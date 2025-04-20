import express, { Request, Response, NextFunction } from 'express';
import fs from 'fs';
import path from 'path';
import session from 'express-session';
import cookieParser from 'cookie-parser';

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
      <li><a href="/users">View Users</a></li>
      <li><a href="/protected">Protected Area</a></li>
    </ul>
  </main>
</body>
</html>`;
  
  res.send(html);
});

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
    res.status(401).send('Invalid credentials');
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

app.get('/protected', authenticate, (req: Request, res: Response) => {
  res.send(`<!DOCTYPE html>
<html>
<head>
  <title>Protected Page</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.classless.min.css">
</head>
<body>
  <main class="container">
    <h1>Protected Area</h1>
    <p>Hello ${req.session.user || 'User'}! This is a protected area.</p>
    <p><a href="/">Back to Home</a></p>
  </main>
</body>
</html>`);
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
  console.log(`CONFIG_USERS: ${process.env.CONFIG_USERS || 'using default path'}`);
});