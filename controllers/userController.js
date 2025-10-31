const User = require('../models/user');

// Get user by ID
exports.getUserById = async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('-password');
    if (!user) return res.status(404).json({
      msg: 'User not found'
    });

    res.json(user);
  } catch (err) {
    console.error(err);
    res.status(500).json({
      msg: 'Server error'
    });
  }
};

// Get all users (Admin only - add auth middleware)
exports.getAllUsers = async (req, res) => {
  try {
    const users = await User.find().select('-password');
    res.json(users);
  } catch (err) {
    console.error(err);
    res.status(500).json({
      msg: 'Server error'
    });
  }
};

// Update user profile
exports.updateUserProfile = async (req, res) => {
  try {
    const userId = req.user?.id || req.params.id;
    const {
      firstName,
      lastName,
      phoneNumber,
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

    const user = await User.findById(userId);
    if (!user) return res.status(404).json({
      msg: 'User not found'
    });

    // Update fields if provided
    if (firstName) user.firstName = firstName;
    if (lastName) user.lastName = lastName;
    if (phoneNumber) user.phoneNumber = phoneNumber;

    // Only update health fields for regular users
    if (user.role === 'user') {
      if (gender) user.gender = gender;
      if (dateOfBirth) user.dateOfBirth = dateOfBirth;
      if (nin) user.nin = nin;
      if (disability) user.disability = disability;
      if (previousHealthIssues) user.previousHealthIssues = previousHealthIssues;
      if (currentHealthIssue) user.currentHealthIssue = currentHealthIssue;
      if (bloodGroup) user.bloodGroup = bloodGroup;
      if (genotype) user.genotype = genotype;
      if (weight) user.weight = weight;
      if (height) user.height = height;
      if (contactAddress) user.contactAddress = contactAddress;
    }

    await user.save();

    res.json({
      msg: 'Profile updated successfully',
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        phoneNumber: user.phoneNumber,
        role: user.role
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({
      msg: 'Server error'
    });
  }
};

// Delete user account
exports.deleteUser = async (req, res) => {
  try {
    const userId = req.params.id;
    const user = await User.findByIdAndDelete(userId);

    if (!user) return res.status(404).json({
      msg: 'User not found'
    });

    res.json({
      msg: 'User deleted successfully'
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({
      msg: 'Server error'
    });
  }
};