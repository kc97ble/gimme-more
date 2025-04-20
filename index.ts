import cookieParser from "cookie-parser";
import dotenv from "dotenv";
import express, { NextFunction, Request, Response } from "express";
import session from "express-session";
import fs from "fs";
import multer from "multer";
import path from "path";
import { z } from "zod";

// Utility functions
const sanitizeFilename = (name: string): string => {
  // Keep only the base name to avoid directory traversal
  const baseName = path.basename(name);
  // Replace non-ASCII characters and path separators
  return baseName.replace(/[^\x00-\x7F]|[\/\\]/g, (match) =>
    encodeURIComponent(match)
  );
};

// Layout function for consistent HTML structure
const layout = ({ title, body }: { title: string; body: string }): string => {
  return `
    <!DOCTYPE html>
    <html>
    <head>
      <title>${title}</title>
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.classless.min.css">
    </head>
    <body>
      ${body}
    </body>
    </html>`;
};

// Load environment variables from .env file
dotenv.config();

interface User {
  username: string;
  password: string;
}

// Extend Express Request type to include session
declare module "express-session" {
  interface SessionData {
    user?: string;
  }
}

// Environment configuration with Zod schema for validation
const Env = z.object({
  CONFIG_USERS: z.string().min(1, "CONFIG_USERS must not be empty"),
  OUTPUT_DIR: z.string().min(1, "OUTPUT_DIR must not be empty"),
  PORT: z.string().regex(/^\d+$/, "PORT must be a number").transform(Number),
  SESSION_SECRET: z
    .string()
    .min(8, "SESSION_SECRET must be at least 8 characters"),
});

type EnvVars = z.infer<typeof Env>;

function getEnv(): EnvVars {
  try {
    // Validate environment variables using Zod
    return Env.parse({
      CONFIG_USERS: process.env.CONFIG_USERS,
      OUTPUT_DIR: process.env.OUTPUT_DIR,
      PORT: process.env.PORT,
      SESSION_SECRET: process.env.SESSION_SECRET,
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      const errorMessages = error.errors
        .map((e) => `- ${e.path.join(".")}: ${e.message}`)
        .join("\n");

      throw new Error(
        `Environment validation failed:\n${errorMessages}\n\nCreate a .env file based on .env.example or set environment variables.`
      );
    }
    throw error;
  }
}

const ENV = getEnv();

const app = express();

// Configure middleware
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(
  session({
    secret: ENV.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 3600000 }, // 1 hour
  })
);

function getUsers(): User[] {
  try {
    const fileContent = fs.readFileSync(ENV.CONFIG_USERS, "utf-8");
    // Split by line breaks and handle whitespace properly
    const lines = fileContent
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line !== "");

    return lines.map((line) => {
      const [username, password] = line.split(":");
      return { username, password };
    });
  } catch (error) {
    console.error("Error reading users file:", error);
    throw new Error(`Failed to read users from ${ENV.CONFIG_USERS}`);
  }
}

const USERS = getUsers();

// Authentication middleware
const authenticate = (
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  // If user is already logged in via session
  if (req.session.user) {
    return next();
  }

  // Get auth header for basic auth
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    res.setHeader("WWW-Authenticate", "Basic");
    res.status(401).send("Authentication required");
    return;
  }

  // Parse credentials
  const auth = Buffer.from(authHeader.split(" ")[1], "base64")
    .toString()
    .split(":");
  const username = auth[0];
  const password = auth[1];

  // Check credentials
  const user = USERS.find(
    (user) => user.username === username && user.password === password
  );

  if (!user) {
    res.setHeader("WWW-Authenticate", "Basic");
    res.status(401).send("Invalid credentials");
    return;
  }

  // Set user in session
  req.session.user = username;
  next();
};

app.get("/login", (_req: Request, res: Response) => {
  res.send(
    layout({
      title: "Login",
      body: `
        <main>
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
        </main>`,
    })
  );
});

app.post("/login", (req: Request, res: Response) => {
  const { username, password } = req.body;

  const user = USERS.find(
    (user) => user.username === username && user.password === password
  );

  if (user) {
    req.session.user = username;
    res.redirect("/");
  } else {
    res.send(
      layout({
        title: "Login Failed",
        body: `
          <main>
            <h1>Login Failed</h1>
            <p>Invalid username or password.</p>
            <p><a href="/login">Try Again</a></p>
            <p><a href="/">Back to Home</a></p>
          </main>`,
      })
    );
  }
});

app.get("/logout", (req: Request, res: Response) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Error destroying session:", err);
    }
    res.redirect("/");
  });
});

app.get("/users", (_req: Request, res: Response) => {
  try {
    const usernames = USERS.map((user) => user.username);

    res.send(
      layout({
        title: "Available Users",
        body: `
          <main>
            <h1>Available Users</h1>
            <ul>
              ${usernames.map((username) => `<li>${username}</li>`).join("")}
            </ul>
            <p><a href="/login">Login</a></p>
            <p><a href="/">Back to Home</a></p>
          </main>`,
      })
    );
  } catch (error) {
    console.error("Error processing users:", error);
    res.status(500).json({ error: "Failed to process users" });
  }
});

// File upload configuration
const MAX_FILE_SIZE = 65536; // 64KB
const ALLOWED_EXTENSIONS = [".c", ".cpp", ".py"];

// Configure multer for file upload
const memoryStorage = multer.memoryStorage();
const upload = multer({
  storage: memoryStorage,
  limits: {
    fileSize: MAX_FILE_SIZE,
  },
  fileFilter: (_req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (ALLOWED_EXTENSIONS.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error(`Only ${ALLOWED_EXTENSIONS.join(", ")} files are allowed`));
    }
  },
});

// Create upload form route
app.get("/upload", authenticate, (_req: Request, res: Response) => {
  res.send(
    layout({
      title: "Upload File",
      body: `
        <main>
          <h1>Upload File</h1>
          <p>Maximum size: 64KB. Allowed extensions: ${ALLOWED_EXTENSIONS.join(
            ", "
          )}</p>
          <form action="/upload" method="POST" enctype="multipart/form-data">
            <div>
              <label for="file">Choose a file:</label>
              <input type="file" id="file" name="file" required>
            </div>
            <button type="submit">Upload</button>
          </form>
          <p><a href="/">Back to Home</a></p>
        </main>`,
    })
  );
});

// Handle file upload
app.post("/upload", authenticate, (req: Request, res: Response) => {
  upload.single("file")(req, res, (err) => {
    if (err instanceof multer.MulterError) {
      if (err.code === "LIMIT_FILE_SIZE") {
        return res.status(400).send("File too large. Maximum size is 64KB.");
      }
      return res.status(400).send(err.message);
    } else if (err) {
      return res.status(400).send(err.message);
    }

    // Continue with the request
    try {
      // Validate that a file was uploaded
      if (!req.file) {
        return res.status(400).send("No file uploaded");
      }

      const username = req.session.user!;
      const userDir = path.join(ENV.OUTPUT_DIR, username);

      const filename = sanitizeFilename(req.file.originalname);

      // Create directories if they don't exist
      if (!fs.existsSync(ENV.OUTPUT_DIR)) {
        fs.mkdirSync(ENV.OUTPUT_DIR, { recursive: true });
      }
      if (!fs.existsSync(userDir)) {
        fs.mkdirSync(userDir, { recursive: true });
      }

      // Save the file
      const filePath = path.join(userDir, filename);
      fs.writeFileSync(filePath, req.file.buffer);

      // Success page
      res.send(
        layout({
          title: "Upload Success",
          body: `
            <main>
              <h1>Upload Successful</h1>
              <p>File <strong>${filename}</strong> uploaded successfully.</p>
              <p>Saved to: ${filePath}</p>
              <p><a href="/upload">Upload Another File</a></p>
              <p><a href="/">Back to Home</a></p>
            </main>`,
        })
      );
    } catch (error) {
      console.error("Error in file upload:", error);
      res.status(500).send("Error uploading file");
    }
  });
});

// List uploaded files
app.get("/list", authenticate, (req: Request, res: Response) => {
  try {
    const username = req.session.user!;
    const userDir = path.join(ENV.OUTPUT_DIR, username);

    // Create directory if it doesn't exist
    if (!fs.existsSync(userDir)) {
      fs.mkdirSync(userDir, { recursive: true });
    }

    // Get list of files
    const files = fs.readdirSync(userDir);

    // File list table HTML
    const fileList =
      files.length > 0
        ? `
          <table>
            <thead><tr><th>Filename</th><th>Size</th><th>Action</th></tr></thead>
            <tbody>
              ${files
                .map((file) => {
                  const stats = fs.statSync(path.join(userDir, file));
                  return `
                  <tr>
                    <td>${file}</td>
                    <td>${(stats.size / 1024).toFixed(2)} KB</td>
                    <td>
                      <form action="/delete" method="POST" style="margin:0">
                        <input type="hidden" name="filename" value="${file}">
                        <button type="submit" class="secondary">Delete</button>
                      </form>
                    </td>
                  </tr>`;
                })
                .join("")}
            </tbody>
          </table>`
        : "<p>No files uploaded yet.</p>";

    res.send(
      layout({
        title: "Your Files",
        body: `
          <main>
            <h1>Your Files</h1>
            <p>Logged in as: ${username}</p>
            ${fileList}
            <p><a href="/upload">Upload New File</a></p>
            <p><a href="/">Back to Home</a></p>
          </main>`,
      })
    );
  } catch (error) {
    console.error("Error listing files:", error);
    res.status(500).send("Error listing files");
  }
});

// Delete file handler
app.post("/delete", authenticate, (req: Request, res: Response) => {
  try {
    const username = req.session.user!;
    const filename = req.body.filename;

    // Validate filename
    if (!filename || typeof filename !== "string") {
      res.status(400).send("Invalid filename");
      return;
    }

    // Sanitize the filename and build the path
    const sanitizedFilename = sanitizeFilename(filename);
    const userDir = path.join(ENV.OUTPUT_DIR, username);
    const filePath = path.join(userDir, sanitizedFilename);

    // Check if file exists
    if (!fs.existsSync(filePath)) {
      res.status(404).send("File not found");
      return;
    }

    // Delete the file
    fs.unlinkSync(filePath);

    // Redirect back to the list page
    res.redirect("/list");
  } catch (error) {
    console.error("Error deleting file:", error);
    res.status(500).send("Error deleting file");
  }
});

// Home page handler
app.get("/", (req: Request, res: Response) => {
  const loggedIn = !!req.session.user;
  const username = req.session.user || "";

  if (loggedIn) {
    res.send(
      layout({
        title: "Home Page",
        body: `
          <main>
            <h1>Welcome</h1>
            <div>
              <p>Logged in as: ${username} <a href="/logout" role="button">Logout</a></p>
              <ul>
                <li><a href="/upload">Upload File</a></li>
                <li><a href="/list">View Your Files</a></li>
              </ul>
            </div>
          </main>`,
      })
    );
  } else {
    res.send(
      layout({
        title: "Home Page",
        body: `
          <main>
            <h1>Welcome</h1>
            <div>
              <p>Not logged in. <a href="/login" role="button">Login</a></p>
              <ul>
                <li><a href="/users">View Users</a></li>
                <li><a href="/uploaded-live">Live Uploads Monitor</a></li>
              </ul>
            </div>
          </main>`,
      })
    );
  }
});

// Route for live updates of uploaded files
app.get("/uploaded-live", (_req: Request, res: Response) => {
  res.send(
    layout({
      title: "Live Uploads Monitor",
      body: `
        <main>
          <h1>Live Uploads Monitor</h1>
          <p>Auto-refreshing every 5 seconds...</p>
          <div style="margin-bottom: 1rem;">
            <button id="refreshButton">Refresh Now</button>
            <span id="lastRefreshed" style="margin-left: 1rem; font-size: 0.9rem; color: #666;"></span>
          </div>
          <pre id="uploadedData" style="background-color: #f5f5f5; padding: 1rem; border-radius: 4px; overflow: auto; max-height: 600px;">Loading...</pre>

          <script>
            // Function to format the current time
            function formatTime() {
              const now = new Date();
              return now.toLocaleTimeString();
            }

            // Function to update the last refreshed time
            function updateLastRefreshed() {
              document.getElementById('lastRefreshed').textContent = 'Last refreshed: ' + formatTime();
            }

            // Function to fetch data from /uploaded endpoint
            async function fetchUploadedData() {
              try {
                document.getElementById('refreshButton').disabled = true;
                const response = await fetch('/uploaded');
                if (!response.ok) {
                  throw new Error('Failed to fetch data');
                }
                const data = await response.text();
                document.getElementById('uploadedData').textContent = data || 'No uploads found';
                updateLastRefreshed();
              } catch (error) {
                console.error('Error fetching data:', error);
                document.getElementById('uploadedData').textContent = 'Error loading data';
              } finally {
                document.getElementById('refreshButton').disabled = false;
              }
            }

            // Attach event listener to refresh button
            document.getElementById('refreshButton').addEventListener('click', fetchUploadedData);

            // Initial fetch
            fetchUploadedData();

            // Set up auto-refresh every 5 seconds
            setInterval(fetchUploadedData, 5000);
          </script>

          <p><a href="/">Back to Home</a></p>
        </main>
      `
    })
  );
});

// Route to list all users and their uploaded files in text format
app.get("/uploaded", (req: Request, res: Response) => {
  try {
    const usernames = USERS.map((user) => user.username);

    // Structure to hold user data with timestamp for sorting
    interface UserData {
      username: string;
      latestTimestamp: Date;
      files: string[];
    }

    // Generate user data objects
    const usersData: UserData[] = [];

    for (const username of usernames) {
      const userDir = path.join(ENV.OUTPUT_DIR, username);

      // Check if user directory exists and has files
      if (fs.existsSync(userDir)) {
        const files = fs.readdirSync(userDir);

        if (files.length > 0) {
          // Get latest modification time from all files
          let latestMtime = new Date(0); // Start with epoch time

          for (const file of files) {
            const filePath = path.join(userDir, file);
            const stats = fs.statSync(filePath);
            if (stats.mtime > latestMtime) {
              latestMtime = stats.mtime;
            }
          }

          usersData.push({
            username,
            latestTimestamp: latestMtime,
            files
          });
        }
      }
    }

    // Sort by latest timestamp (most recent first)
    usersData.sort((a, b) => b.latestTimestamp.getTime() - a.latestTimestamp.getTime());

    // Convert to output format
    const outputLines = usersData.map(userData => {
      const timestamp = userData.latestTimestamp.toISOString();
      return `${timestamp} ${userData.username}: ${userData.files.join(", ")}`;
    });

    // Send text response
    res.setHeader("Content-Type", "text/plain");
    res.send(outputLines.join("\n"));
  } catch (error) {
    console.error("Error generating uploaded files list:", error);
    res.status(500).send("Error generating uploaded files list");
  }
});

app.listen(ENV.PORT, () => {
  console.log(`Server running at http://localhost:${ENV.PORT}`);
  console.log(`CONFIG_USERS: ${ENV.CONFIG_USERS}`);
  console.log(`OUTPUT_DIR: ${ENV.OUTPUT_DIR}`);
});
