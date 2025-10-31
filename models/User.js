const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const userSchema = new mongoose.Schema({
    firstName: {
        type: String,
        required: [true, 'Please enter your first name'],
        trim: true,
    },
    lastName: {
        type: String,
        required: [true, 'Please enter your last name'],
        trim: true,
    },
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true
    },
    phoneNumber: {
        type: String,
        required: [true, 'Please enter your phone number'],
        unique: true,
    },
    password: {
        type: String,
        required: true
    },
    role: {
        type: String,
        enum: ['user', 'admin'],
        default: 'user',
    },
    // Fields only for regular users (not required for admins)
    gender: {
        type: String,
        enum: ['Male', 'Female', 'Other'],
        required: function () {
            return this.role === 'user';
        }
    },
    dateOfBirth: {
        type: Date,
        required: function () {
            return this.role === 'user';
        }
    },
    nin: {
        type: String,
        required: function () {
            return this.role === 'user';
        },
        unique: true,
        sparse: true // Allows null values for admins
    },
    disability: {
        type: String,
        enum: ['None', 'Physical', 'Visual', 'Hearing', 'Mental', 'Other'],
        default: 'None',
        required: function () {
            return this.role === 'user';
        }
    },
    previousHealthIssues: {
        type: String,
        default: 'None',
        required: function () {
            return this.role === 'user';
        }
    },
    currentHealthIssue: {
        type: String,
        default: 'None',
        required: function () {
            return this.role === 'user';
        }
    },
    bloodGroup: {
        type: String,
        enum: ['A+', 'A-', 'B+', 'B-', 'AB+', 'AB-', 'O+', 'O-'],
        required: function () {
            return this.role === 'user';
        }
    },
    genotype: {
        type: String,
        enum: ['AA', 'AS', 'SS', 'AC', 'SC'],
        required: function () {
            return this.role === 'user';
        }
    },
    weight: {
        type: Number,
        required: function () {
            return this.role === 'user';
        }
    },
    height: {
        type: Number,
        required: function () {
            return this.role === 'user';
        }
    },
    contactAddress: {
        type: String,
        required: function () {
            return this.role === 'user';
        }
    },
    isVerified: {
        type: Boolean,
        default: false
    },
    verifyToken: String,
    verifyTokenExpires: Date,
    resetPasswordToken: String,
    resetPasswordExpires: Date
}, {
    timestamps: true
});

// Hash password before saving
userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) return next();

    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
});

// Generate email verification token (instance method)
userSchema.methods.generateVerificationToken = function () {
    const token = crypto.randomBytes(32).toString('hex');
    this.verifyToken = crypto.createHash('sha256').update(token).digest('hex');
    this.verifyTokenExpires = Date.now() + 1000 * 60 * 60; // 1 hour expiry
    return token;
};

module.exports = mongoose.model('User', userSchema);