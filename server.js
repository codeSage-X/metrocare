// server.js

const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const authRoutes = require('./routes/authRoutes')

// Load environment variables
dotenv.config();

const app = express();
app.use(express.json());

// --- Connect to MongoDB Atlas ---
mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log('✅ Connected to MongoDB Atlas'))
    .catch((err) => console.error('❌ MongoDB connection error:', err));

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/users', require('./routes/userRoutes'));


// --- Routes ---
app.get('/', (req, res) => {
    res.send('Welcome to Metro Server connected to MongoDB Atlas');
});

// --- Start the server ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Server running on http://localhost:${PORT}`));