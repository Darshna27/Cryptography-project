const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const crypto = require('crypto');
const fs = require('fs');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const app = express();
const port = 3000;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// JWT Secret Key
const JWT_SECRET = 'your_secret_key';

// MongoDB connection
mongoose.connect('mongodb://localhost:27017/healthcrypt', { useNewUrlParser: true, useUnifiedTopology: true });

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'connection error:'));
db.once('open', () => {
    console.log('Connected to MongoDB');
});

// Define User schema and model
const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    email: String,
    phone: String
});

const User = mongoose.model('User', userSchema);

// Setup multer for file uploads
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

// Serve HTML files
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/signup.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});

app.get('/dashboard.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Signup Route
app.post('/signup', async (req, res) => {
    const { username, password, email, phone } = req.body;
    if (!username || !password || !email || !phone) {
        return res.status(400).send('All fields are required.');
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, password: hashedPassword, email, phone });
    try {
        await newUser.save();
        res.redirect('/');
    } catch (error) {
        console.error('Error saving user:', error);
        res.status(500).send('Error signing up');
    }
});

// Login Route
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await User.findOne({ username: username });
        if (!user) {
            return res.status(401).send('Invalid username or password.');
        }
        const match = await bcrypt.compare(password, user.password);
        if (match) {
            const token = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: '1h' });
            res.cookie('token', token, { httpOnly: true });
            res.redirect('/dashboard.html');
        } else {
            res.status(401).send('Invalid username or password.');
        }
    } catch (error) {
        console.error('Error finding user:', error);
        res.status(500).send('Error logging in');
    }
});

// Encryption Route
app.post('/encrypt', upload.single('file'), (req, res) => {
    const key = req.body.key;
    const file = req.file ? req.file.buffer : null;

    if (!key || !file) {
        return res.status(400).send('Key and file are required.');
    }

    try {
        // Generate a random IV (Initialization Vector)
        const iv = crypto.randomBytes(16);

        // Ensure key is in a suitable format
        let keyBuffer = Buffer.from(key, 'utf-8');
        
        // Pad or trim the key to make it 32 bytes long for AES-256
        if (keyBuffer.length < 32) {
            keyBuffer = Buffer.concat([keyBuffer, Buffer.alloc(32 - keyBuffer.length)], 32);
        } else if (keyBuffer.length > 32) {
            keyBuffer = keyBuffer.slice(0, 32);
        }

        const cipher = crypto.createCipheriv('aes-256-cbc', keyBuffer, iv);
        let encrypted = Buffer.concat([cipher.update(file), cipher.final()]);

        const downloadDir = path.join(__dirname, 'public', 'downloads');
        if (!fs.existsSync(downloadDir)) {
            fs.mkdirSync(downloadDir);
        }

        const encryptedFileName = `${uuidv4()}.enc`;
        const encryptedFilePath = path.join(downloadDir, encryptedFileName);
        const ivFilePath = encryptedFilePath + '.iv';

        // Save the encrypted file and IV
        fs.writeFileSync(encryptedFilePath, encrypted);
        fs.writeFileSync(ivFilePath, iv);

        console.log('File encrypted successfully');
        res.json({ message: 'File encrypted and saved successfully', filePath: `downloads/${encryptedFileName}` });
    } catch (error) {
        console.error('Encryption error:', error);
        res.status(500).send('Error encrypting file');
    }
});

// Decryption Route
app.post('/decrypt', upload.single('file'), (req, res) => {
    const key = req.body.key;
    const file = req.file ? req.file.buffer : null;

    if (!key || !file) {
        return res.status(400).send('Key and file are required.');
    }

    try {
        // Read the IV
        const ivFilePath = path.join(__dirname, 'public', 'downloads', req.file.originalname + '.iv');
        if (!fs.existsSync(ivFilePath)) {
            return res.status(400).send('No IV found for this file.');
        }
        const iv = fs.readFileSync(ivFilePath);

        // Ensure key is in a suitable format
        let keyBuffer = Buffer.from(key, 'utf-8');
        
        // Pad or trim the key to make it 32 bytes long for AES-256
        if (keyBuffer.length < 32) {
            keyBuffer = Buffer.concat([keyBuffer, Buffer.alloc(32 - keyBuffer.length)], 32);
        } else if (keyBuffer.length > 32) {
            keyBuffer = keyBuffer.slice(0, 32);
        }

        const decipher = crypto.createDecipheriv('aes-256-cbc', keyBuffer, iv);
        let decrypted = Buffer.concat([decipher.update(file), decipher.final()]);

        const filePath = path.join(__dirname, 'public', 'downloads', 'decryptedFile.png');

        // Save the decrypted file
        fs.writeFileSync(filePath, decrypted);

        console.log('File decrypted successfully');
        res.download(filePath, 'decryptedFile.png', (err) => {
            if (err) {
                console.error('Error sending decrypted file:', err);
            }
            fs.unlinkSync(filePath);
        });
    } catch (error) {
        console.error('Decryption error:', error);
        res.status(500).send('Error decrypting file');
    }
});

// Start the server
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
