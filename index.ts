import express, { Request, Response } from 'express';
import fs from 'fs';
import path from 'path';

interface User {
  username: string;
  password: string;
}

const app = express();
const port = 3000;

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

app.get('/', (req: Request, res: Response) => {
  res.send('Hello World!');
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

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
  console.log(`CONFIG_USERS: ${process.env.CONFIG_USERS || 'not set'}`);
});