const User = require('../models/user');
const BlacklistedToken = require('../models/BlacklistedToken');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

// Helper function to generate JWT
const generateToken = (userId) => {
  const payload = {
    user: {
      id: userId
    }
  };
  return jwt.sign(payload, process.env.JWT_SECRET, {
    expiresIn: '30d'
  });
};

// Helper function to get user response object (for regular users)
const getUserResponse = (user) => {
  const response = {
    id: user._id,
    firstName: user.firstName,
    lastName: user.lastName,
    email: user.email,
    phoneNumber: user.phoneNumber,
    role: user.role,
    isVerified: user.isVerified
  };

  // Only include additional fields for regular users
  if (user.role === 'user') {
    response.gender = user.gender;
    response.dateOfBirth = user.dateOfBirth;
    response.nin = user.nin;
    response.disability = user.disability;
    response.previousHealthIssues = user.previousHealthIssues;
    response.currentHealthIssue = user.currentHealthIssue;
    response.bloodGroup = user.bloodGroup;
    response.genotype = user.genotype;
    response.weight = user.weight;
    response.height = user.height;
    response.contactAddress = user.contactAddress;
  }

  return response;
};

exports.register = async (req, res) => {
  const {
    firstName,
    lastName,
    email,
    password,
    phoneNumber,
    adminKey,
    // User-specific fields
    gender,
    dateOfBirth,
    nin,
    disability,
    previousHealthIssues,
    currentHealthIssue,
    bloodGroup,
    genotype,
    weight,
    height,
    contactAddress
  } = req.body;

  // Check if it's an admin registration
  let role = 'user';
  if (adminKey) {
    console.log('Received adminKey:', adminKey);
    console.log('Expected ADMIN_SECRET_KEY:', process.env.ADMIN_SECRET_KEY);
    if (adminKey !== process.env.ADMIN_SECRET_KEY) {
      return res.status(400).json({
        msg: 'Invalid admin key',
        received: adminKey,
        expected: process.env.ADMIN_SECRET_KEY
      });
    }
    role = 'admin';
  }

  try {
    let existingUser = await User.findOne({
      email
    });
    if (existingUser) {
      return res.status(400).json({
        msg: 'User already exists'
      });
    }

    // Check if phone number is already in use
    const existingPhoneUser = await User.findOne({
      phoneNumber
    });
    if (existingPhoneUser) {
      return res.status(400).json({
        msg: 'Phone number is already registered'
      });
    }

    // Check if NIN is already in use (only for regular users)
    if (role === 'user' && nin) {
      const existingNinUser = await User.findOne({
        nin
      });
      if (existingNinUser) {
        return res.status(400).json({
          msg: 'NIN is already registered'
        });
      }
    }

    let user;
    try {
      // First verify email configuration
      if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
        throw new Error('Email configuration is missing');
      }

      // Create user object based on role
      const userData = {
        firstName,
        lastName,
        email,
        password,
        phoneNumber,
        role
      };

      // Add user-specific fields only if role is 'user'
      if (role === 'user') {
        userData.gender = gender;
        userData.dateOfBirth = dateOfBirth;
        userData.nin = nin;
        userData.disability = disability || 'None';
        userData.previousHealthIssues = previousHealthIssues || 'None';
        userData.currentHealthIssue = currentHealthIssue || 'None';
        userData.bloodGroup = bloodGroup;
        userData.genotype = genotype;
        userData.weight = weight;
        userData.height = height;
        userData.contactAddress = contactAddress;
      }

      // Create user instance but don't save yet
      user = new User(userData);

      // Generate a 6-digit OTP
      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      const hashedOTP = crypto.createHash('sha256').update(otp).digest('hex');

      user.verifyToken = hashedOTP;
      user.verifyTokenExpires = Date.now() + 10 * 60 * 1000; // 10 minutes

      // Create email transporter
      const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
          user: process.env.EMAIL_USER,
          pass: process.env.EMAIL_PASS
        }
      });

      // Test email connection
      await transporter.verify();

      // Try to send email
      await transporter.sendMail({
        from: `"Metro App" <${process.env.EMAIL_USER}>`,
        to: email,
        subject: 'Your Email Verification Code',
        html: `
          <p>Hi ${firstName},</p>
          <p>Your verification code is:</p>
          <h2>${otp}</h2>
          <p>This code will expire in 10 minutes.</p>
        `
      });

      // Only save user after email is sent successfully
      await user.save();

      res.status(201).json({
        msg: 'Registration successful. Please check your email for the verification code.'
      });

    } catch (err) {
      // If user was created but email failed, delete the user
      if (user && user._id) {
        await User.findByIdAndDelete(user._id);
      }

      console.error('Registration error:', err);

      // Send appropriate error message
      if (err.code === 'EAUTH') {
        return res.status(500).json({
          msg: 'Failed to send verification email. Please try again later.'
        });
      }

      // Check for validation errors
      if (err.name === 'ValidationError') {
        const errors = Object.values(err.errors).map(e => e.message);
        return res.status(400).json({
          msg: 'Validation error',
          errors: errors
        });
      }

      res.status(500).json({
        msg: 'Registration failed. Please try again later.'
      });
    }

  } catch (err) {
    console.error(err);
    res.status(500).json({
      msg: 'Server error'
    });
  }
};

exports.login = async (req, res) => {
  const {
    email,
    password
  } = req.body;

  try {
    const user = await User.findOne({
      email
    });
    if (!user) return res.status(400).json({
      msg: 'Invalid credentials'
    });

    if (!user.isVerified) {
      return res.status(401).json({
        msg: 'Please verify your email before logging in.'
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({
      msg: 'Invalid credentials'
    });

    const token = generateToken(user._id);

    res.json({
      token,
      user: getUserResponse(user)
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({
      msg: 'Server error'
    });
  }
};

exports.verifyEmail = async (req, res) => {
  const {
    email,
    otp
  } = req.body;

  if (!email || !otp) {
    return res.status(400).json({
      msg: 'Email and OTP are required'
    });
  }

  try {
    const user = await User.findOne({
      email
    });
    if (!user) return res.status(404).json({
      msg: 'User not found'
    });

    if (!user.verifyTokenExpires || user.verifyTokenExpires < Date.now()) {
      return res.status(400).json({
        msg: 'OTP has expired. Please request a new one.'
      });
    }

    const hashedOTP = crypto.createHash('sha256').update(otp).digest('hex');

    if (user.verifyToken !== hashedOTP) {
      return res.status(400).json({
        msg: 'Invalid OTP. Please check and try again.'
      });
    }

    user.isVerified = true;
    user.verifyToken = undefined;
    user.verifyTokenExpires = undefined;
    await user.save();

    res.status(200).json({
      msg: 'Email verified successfully. You can now log in.'
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({
      msg: 'Server error'
    });
  }
};

exports.resendVerificationEmail = async (req, res) => {
  const {
    email
  } = req.body;

  try {
    const user = await User.findOne({
      email
    });
    if (!user) return res.status(404).json({
      msg: 'User not found'
    });

    if (user.isVerified) {
      return res.status(400).json({
        msg: 'Email already verified'
      });
    }

    // ⏱️ Check if OTP was recently sent (within 60 seconds)
    if (user.verifyTokenExpires && Date.now() < user.verifyTokenExpires - (9 * 60 * 1000)) {
      return res.status(429).json({
        msg: 'OTP already sent recently. Please wait before requesting another.'
      });
    }

    // Generate new OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const hashedOTP = crypto.createHash('sha256').update(otp).digest('hex');

    user.verifyToken = hashedOTP;
    user.verifyTokenExpires = Date.now() + 10 * 60 * 1000; // valid for 10 minutes
    await user.save();

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      }
    });

    await transporter.sendMail({
      from: `"Metro App" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Your Verification Code (Resent)',
      html: `
        <p>Hi ${user.firstName},</p>
        <p>Your new verification code is:</p>
        <h2>${otp}</h2>
        <p>This code will expire in 10 minutes.</p>
      `
    });

    res.status(200).json({
      msg: 'Verification code resent successfully'
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({
      msg: 'Server error'
    });
  }
};

// FORGOT PASSWORD - Send OTP
exports.forgotPassword = async (req, res) => {
  const {
    email
  } = req.body;

  try {
    const user = await User.findOne({
      email
    });
    if (!user) return res.status(404).json({
      msg: 'User not found'
    });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const hashedOTP = crypto.createHash('sha256').update(otp).digest('hex');

    user.resetPasswordToken = hashedOTP;
    user.resetPasswordExpires = Date.now() + 10 * 60 * 1000; // 10 minutes
    await user.save();

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      }
    });

    await transporter.sendMail({
      from: `"Pages App" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Reset Your Password',
      html: `
        <p>Hi ${user.firstName},</p>
        <p>Your password reset OTP is:</p>
        <h2>${otp}</h2>
        <p>This code will expire in 10 minutes.</p>
      `
    });

    res.status(200).json({
      msg: 'Reset code sent to email'
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({
      msg: 'Server error'
    });
  }
};

// RESET PASSWORD with OTP
exports.resetPassword = async (req, res) => {
  const {
    email,
    otp,
    newPassword
  } = req.body;

  try {
    const user = await User.findOne({
      email
    });
    if (!user) return res.status(404).json({
      msg: 'User not found'
    });

    if (!user.resetPasswordExpires || user.resetPasswordExpires < Date.now()) {
      return res.status(400).json({
        msg: 'OTP has expired. Please request a new one.'
      });
    }

    const hashedOTP = crypto.createHash('sha256').update(otp).digest('hex');

    if (user.resetPasswordToken !== hashedOTP) {
      return res.status(400).json({
        msg: 'Invalid OTP. Please check and try again.'
      });
    }

    // Set the new password directly and let the pre-save middleware handle hashing
    user.password = newPassword;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    res.status(200).json({
      msg: 'Password reset successful. You can now log in.'
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({
      msg: 'Server error'
    });
  }
};

// CHANGE PASSWORD (Authenticated)
exports.changePassword = async (req, res) => {
  const {
    currentPassword,
    newPassword
  } = req.body;
  const userId = req.user?.id;

  try {
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({
      msg: 'User not found'
    });

    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) return res.status(400).json({
      msg: 'Current password is incorrect'
    });

    // Set the new password directly and let the pre-save middleware handle hashing
    user.password = newPassword;
    await user.save();

    res.status(200).json({
      msg: 'Password changed successfully'
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({
      msg: 'Server error'
    });
  }
};

// Updated logout function
exports.logout = async (req, res) => {
  try {
    const token = req.header('Authorization')?.split(' ')[1];
    if (!token) return res.status(400).json({
      msg: 'No token provided'
    });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Add token to blacklist
    await BlacklistedToken.create({
      token: token,
      expiresAt: new Date(decoded.exp * 1000)
    });

    res.status(200).json({
      msg: 'Successfully logged out'
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({
      msg: 'Server error'
    });
  }
};