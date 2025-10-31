const jwt = require('jsonwebtoken');
const User = require('../models/user');
const BlacklistedToken = require('../models/BlacklistedToken');

module.exports = async (req, res, next) => {
    try {
        // Get token from header
        const token = req.header('Authorization')?.split(' ')[1];
        if (!token) {
            return res.status(401).json({
                msg: 'No token, authorization denied'
            });
        }

        // Check if token is blacklisted
        const blacklistedToken = await BlacklistedToken.findOne({
            token
        });
        if (blacklistedToken) {
            return res.status(401).json({
                msg: 'Token is no longer valid'
            });
        }

        // Verify token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        // Get user from database
        const user = await User.findById(decoded.user.id).select('-password');
        if (!user) {
            return res.status(401).json({
                msg: 'User not found'
            });
        }

        // Add user to request object
        req.user = user;
        next();
    } catch (err) {
        res.status(401).json({
            msg: 'Token is not valid'
        });
    }
};