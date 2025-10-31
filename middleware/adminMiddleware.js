const isAdmin = (req, res, next) => {
    // Check if user exists and has admin role
    if (!req.user || req.user.role !== 'admin') {
        return res.status(403).json({
            msg: 'Access denied. Admin privileges required.'
        });
    }
    next();
};

module.exports = isAdmin;