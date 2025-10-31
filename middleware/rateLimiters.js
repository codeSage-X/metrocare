const rateLimit = require('express-rate-limit');

// Auth rate limiter (login, register)
exports.authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Limit each IP to 5 requests per windowMs
    message: 'Too many attempts, please try again after 15 minutes'
});

// Password reset rate limiter
exports.passwordResetLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 3, // Limit each IP to 3 requests per windowMs
    message: 'Too many password reset attempts, please try again after an hour'
});