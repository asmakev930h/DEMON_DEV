const express = require('express');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');

const app = express();
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// Path to store user data
const userDir = path.join(__dirname, 'user');

// Ensure user directory exists
if (!fs.existsSync(userDir)) {
    fs.mkdirSync(userDir);
}

// Registration Endpoint
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    const userFile = path.join(userDir, `${username}.json`);

    if (fs.existsSync(userFile)) {
        return res.status(400).json({ message: 'Username already exists' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const userData = { username, password: hashedPassword };

        fs.writeFileSync(userFile, JSON.stringify(userData, null, 2));
        res.json({ message: 'User registered successfully' });
    } catch (err) {
        res.status(500).json({ message: 'Error registering user', error: err.message });
    }
});

// Login Endpoint
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const userFile = path.join(userDir, `${username}.json`);

    if (!fs.existsSync(userFile)) {
        return res.status(400).json({ message: 'User not found' });
    }

    try {
        const userData = JSON.parse(fs.readFileSync(userFile, 'utf-8'));
        const isMatch = await bcrypt.compare(password, userData.password);

        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        res.json({ message: 'Login successful' });
    } catch (err) {
        res.status(500).json({ message: 'Error logging in', error: err.message });
    }
});

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
