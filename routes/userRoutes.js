const express = require('express');
const router = express.Router();
const {
  getAllUsers,
  getUserById,
  updateUserProfile,
  deleteUser
} = require('../controllers/userController');
const authMiddleware = require('../middleware/authMiddleware');

// Base path: /api/users

router.get('/', authMiddleware, getAllUsers); // GET /api/users
router.get('/:id', authMiddleware, getUserById); // GET /api/users/:id
router.put('/:id', authMiddleware, updateUserProfile); // PUT /api/users/:id
router.delete('/:id', authMiddleware, deleteUser); // DELETE /api/users/:i

module.exports = router;