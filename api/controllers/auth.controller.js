import bcryptjs from 'bcryptjs';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import User from '../models/user.model.js';
import { errorHandler } from '../utils/error.js';

// Password complexity criteria
const MIN_PASSWORD_LENGTH = 8;
const PASSWORD_REGEX = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[\W_]).{8,}$/;

// Avatar upload configuration using multer
const avatarUpload = multer({
  limits: { fileSize: 2 * 1024 * 1024 }, // Limit avatar size to 2MB
  storage: multer.memoryStorage(),
}).single('avatar');

// Email validation regex
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Login attempts tracking
const MAX_LOGIN_ATTEMPTS = 3;
const BAN_DURATION = 30000; // 30 seconds in milliseconds
const loginAttempts = new Map();

export const signup = async (req, res, next) => {
  const { username, email, password } = req.body;

  try {
    // Validate password complexity
    if (!PASSWORD_REGEX.test(password) || password.length < MIN_PASSWORD_LENGTH) {
      return next(errorHandler(400, 'Password must be unique !'));
    }

    // Validate email format
    if (!validateEmail(email)) {
      return next(errorHandler(400, 'Invalid email format'));
    }

    const hashedPassword = await bcryptjs.hash(password, 10);
    const newUser = new User({ username, email, password: hashedPassword });
    await newUser.save();
    res.status(201).json('User created successfully!');
  } catch (error) {
    next(error);
  }
};

export const signin = async (req, res, next) => {
  const { email, password } = req.body;

  try {
    // Check if the user is temporarily banned
    const banExpiration = loginAttempts.get(email);
    if (banExpiration && banExpiration > Date.now()) {
      const remainingTime = Math.ceil((banExpiration - Date.now()) / 1000);
      return next(errorHandler(403, `User is temporarily banned. Try again in ${remainingTime} seconds.`));
    }

    const validUser = await User.findOne({ email });

    if (!validUser) {
      handleInvalidLogin(email);
      return next(errorHandler(401, 'Enter valid e-mail address !'));
    }

    const validPassword = await bcryptjs.compare(password, validUser.password);

    if (!validPassword) {
      handleInvalidLogin(email);
      return next(errorHandler(401, 'Please enter correct password !'));
    }

    // Successful login, reset login attempts
    loginAttempts.delete(email);

    const token = jwt.sign({ id: validUser._id }, process.env.JWT_SECRET, { expiresIn: '90d' });
    const { password: pass, ...rest } = validUser._doc;

    res
      .cookie('access_token', token, { httpOnly: true })
      .status(200)
      .json(rest);
  } catch (error) {
    next(error);
  }
};

export const google = async (req, res, next) => {
  try {
    const { email, name, photo } = req.body;

    // Validate email format
    if (!validateEmail(email)) {
      return next(errorHandler(400, 'Invalid email format'));
    }

    const user = await User.findOne({ email });

    if (user) {
      const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
      const { password: pass, ...rest } = user._doc;
      res
        .cookie('access_token', token, { httpOnly: true })
        .status(200)
        .json(rest);
    } else {
      const generatedPassword =
        Math.random().toString(36).slice(-8) +
        Math.random().toString(36).slice(-8);
      const hashedPassword = await bcryptjs.hash(generatedPassword, 10);

      const newUser = new User({
        username: name.split(' ').join('').toLowerCase() + Math.random().toString(36).slice(-4),
        email,
        password: hashedPassword,
        avatar: photo,
      });

      await newUser.save();
      const token = jwt.sign({ id: newUser._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
      const { password: pass, ...rest } = newUser._doc;
      res
        .cookie('access_token', token, { httpOnly: true })
        .status(200)
        .json(rest);
    }
  } catch (error) {
    next(error);
  }
};

export const signOut = async (req, res, next) => {
  try {
    res.clearCookie('access_token');
    res.status(200).json('User has been logged out!');
  } catch (error) {
    next(error);
  }
};

export const updateUser = async (req, res, next) => {
  if (req.user.id !== req.params.id)
    return next(errorHandler(401, 'You can only update your own account!'));

  // Use the avatar upload middleware to handle file size and type validation
  avatarUpload(req, res, async (avatarUploadError) => {
    if (avatarUploadError) {
      return next(errorHandler(400, avatarUploadError.message));
    }

    try {
      if (req.body.password) {
        req.body.password = bcryptjs.hashSync(req.body.password, 10);
      }

      const updatedUser = await User.findByIdAndUpdate(
        req.params.id,
        {
          $set: {
            username: req.body.username,
            email: req.body.email,
            password: req.body.password,
            avatar: req.file ? req.file.buffer : undefined, // Store avatar buffer if uploaded
          },
        },
        { new: true }
      );

      const { password, ...rest } = updatedUser._doc;

      res.status(200).json(rest);
    } catch (error) {
      next(error);
    }
  });
};

// Helper function to handle invalid login attempts
const handleInvalidLogin = (email) => {
  // Increment login attempts
  const attempts = loginAttempts.get(email) || 0;
  loginAttempts.set(email, attempts + 1);

  // Check if the user has reached the maximum login attempts
  if (attempts + 1 >= MAX_LOGIN_ATTEMPTS) {
    // Set ban expiration time
    const banExpirationTime = Date.now() + BAN_DURATION;
    loginAttempts.set(email, banExpirationTime);
  }
};

// Email validation function
const validateEmail = (email) => {
  return EMAIL_REGEX.test(email);
};
