require('dotenv').config(); // Use environment variables for sensitive data
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
// --- UPDATED IMPORT ---
const Player = require('./models/Player'); // Import the new Player model
// --- EXISTING IMPORTS ---
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs'); 
const Admin = require('./models/Admin'); // Import Admin model
// ...

const app = express();
const PORT = process.env.PORT || 5001;
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/footballturf';

// Middleware
app.use(cors()); // Allows frontend to make requests
app.use(express.json()); // Parses incoming JSON requests

// MongoDB Connection
mongoose.connect(MONGODB_URI)
    .then(() => console.log('MongoDB connected successfully.'))
    .catch(err => console.error('MongoDB connection error:', err));


// Helper function to generate JWT
const generateToken = (id) => {
    return jwt.sign({ id }, process.env.JWT_SECRET || 'YOUR_SECRET_KEY', {
        expiresIn: '1d',
    });
};

// POST /api/admin/login - Authenticate Admin
app.post('/api/admin/login', async (req, res) => {
    const { username, password } = req.body;

    const admin = await Admin.findOne({ username });

    if (admin && (await admin.matchPassword(password))) {
        res.json({
            message: 'Login successful',
            token: generateToken(admin._id),
            username: admin.username,
        });
    } else {
        res.status(401).json({ message: 'Invalid username or password' });
    }
});

// Middleware to protect routes (checks for a valid JWT in the header)
const protect = async (req, res, next) => {
    let token;

    // Check for token in the Authorization header (Bearer <token>)
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        try {
            // Get token from header
            token = req.headers.authorization.split(' ')[1];

            // Verify token and extract payload (admin ID)
            const decoded = jwt.verify(token, process.env.JWT_SECRET || 'YOUR_SECRET_KEY'); 

            // Fetch admin from database
            req.admin = await Admin.findById(decoded.id).select('-password');

            next(); // Proceed to the next middleware/route handler
        } catch (error) {
            console.error('Token verification failed:', error);
            res.status(401).json({ message: 'Not authorized, token failed' });
        }
    }

    if (!token) {
        res.status(401).json({ message: 'Not authorized, no token' });
    }
};

// --- API Routes ---

// 1. POST /api/users - Register a new player
app.post('/api/users', protect, async (req, res) => {
    try {
        // Destructure all fields from the Player Schema
        const {
            fullName,
            dateOfBirth,
            gender,
            nationality,
            city,
            postalCode,
            residentialAddress,
            parentGuardianName,
            contactNumber,
            allergies,
            relationshipToPlayer,
            emailAddress, // Unique identifier
            emergencyConditions,
            emergencyContactNumber,
            bloodType,
            physicianName,
            physicianContactNumber,
            allowPromotionalMedia,
            isPaid
        } = req.body;
        
        // **Basic Validation for Required Fields**
        if (!fullName || !dateOfBirth || !gender || !parentGuardianName || !contactNumber || !emailAddress) {
             return res.status(400).json({ message: 'Missing required player and guardian details (Full Name, DOB, Gender, Guardian Name, Contact #, Email).' });
        }

        // Create a new Player instance
        const newPlayer = new Player({
            fullName,
            dateOfBirth,
            gender,
            nationality,
            city,
            postalCode,
            residentialAddress,
            parentGuardianName,
            contactNumber,
            allergies,
            relationshipToPlayer,
            emailAddress,
            emergencyConditions,
            emergencyContactNumber,
            bloodType,
            physicianName,
            physicianContactNumber,
            allowPromotionalMedia: allowPromotionalMedia || false,
            isPaid: isPaid || false
        });

        // Save the player to the database
        const savedPlayer = await newPlayer.save();
        res.status(201).json(savedPlayer);
    } catch (error) {
        // Handle duplicate email error
        if (error.code === 11000) {
            return res.status(400).json({ message: 'Email address already registered.' });
        }
        // Handle Mongoose Validation errors (e.g., failed required field checks)
        if (error.name === 'ValidationError') {
            return res.status(400).json({ message: `Validation Error: ${error.message}` });
        }
        console.error(error);
        res.status(500).json({ message: 'Server error during player registration.' });
    }
});

// 2. GET /api/users - Get all registered players
app.get('/api/users', protect, async (req, res) => {
    try {
        // Fetch all players using the Player model
        const players = await Player.find().sort({ registeredAt: -1 }); 
        res.status(200).json(players);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error fetching players.' });
    }
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});