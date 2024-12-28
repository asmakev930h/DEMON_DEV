const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const fs = require("fs");
const { exec } = require("child_process");
const path = require("path");

const app = express();
app.use(bodyParser.json());
app.use(express.static("public"));

const usersDir = "./users"; // User directories

// Ensure users directory exists
if (!fs.existsSync(usersDir)) {
  fs.mkdirSync(usersDir);
}

// Middleware to check authentication
const authenticate = (req, res, next) => {
  const username = req.query.username;
  const token = req.query.token;

  if (!username || !token) return res.status(401).send("Unauthorized");

  const userFile = path.join(usersDir, username, "user.json");
  if (fs.existsSync(userFile)) {
    const userData = JSON.parse(fs.readFileSync(userFile, "utf-8"));
    if (userData.token === token) {
      req.user = username;
      return next();
    }
  }
  res.status(401).send("Unauthorized");
};

// Register endpoint
app.post("/register", (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).send("Username and password are required.");
  }

  const userPath = path.join(usersDir, username);
  if (fs.existsSync(userPath)) {
    return res.status(400).send("User already exists.");
  }

  fs.mkdirSync(userPath);
  const hashedPassword = bcrypt.hashSync(password, 10);
  const token = Math.random().toString(36).substring(2);
  fs.writeFileSync(
    path.join(userPath, "user.json"),
    JSON.stringify({ username, password: hashedPassword, token })
  );

  res.status(201).send({ message: "User registered successfully.", token });
});

// Login endpoint
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  const userPath = path.join(usersDir, username);
  if (!fs.existsSync(userPath)) {
    return res.status(400).send("Invalid username or password.");
  }

  const userData = JSON.parse(
    fs.readFileSync(path.join(userPath, "user.json"), "utf-8")
  );

  if (bcrypt.compareSync(password, userData.password)) {
    res.status(200).send({
      message: "Login successful.",
      token: userData.token,
    });
  } else {
    res.status(400).send("Invalid username or password.");
  }
});

// Execute command endpoint
app.post("/execute", authenticate, (req, res) => {
  const { command } = req.body;
  const userDir = path.join(usersDir, req.user);

  if (!command) {
    return res.status(400).send("Command is required.");
  }

  exec(command, { cwd: userDir }, (error, stdout, stderr) => {
    if (error) {
      return res.status(500).send(`Error: ${error.message}`);
    }
    if (stderr) {
      return res.status(500).send(`Stderr: ${stderr}`);
    }
    res.status(200).send(stdout);
  });
});

// Serve terminal page
app.get("/terminal", authenticate, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "terminal.html"));
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
