import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import express from 'express';
import fs from 'fs';
import mongoose from 'mongoose';
import morgan from 'morgan';
import path from 'path';
import authRouter from './routes/auth.route.js';
import listingRouter from './routes/listing.route.js';
import userRouter from './routes/user.route.js';

dotenv.config();

// Connect to MongoDB
mongoose
  .connect(process.env.MONGO)
  .then(() => {
    console.log('Connected to MongoDB!');
  })
  .catch((err) => {
    console.error(err);
  });

const __dirname = path.resolve();

const app = express();

// Create a write stream for the log file
const logStream = fs.createWriteStream(path.join(__dirname, 'access.log'), { flags: 'a' });

// Use Morgan middleware for logging HTTP requests to the console and file
app.use(morgan('combined', { stream: logStream }));
app.use(express.json());
app.use(cookieParser());

// Routes
app.use('/api/user', userRouter);
app.use('/api/auth', authRouter);
app.use('/api/listing', listingRouter);

// Serve static files from the 'client/dist' directory
app.use(express.static(path.join(__dirname, 'client', 'dist')));

// Handle all other routes by serving the Angular app
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'client', 'dist', 'index.html'));
});

// Error handling middleware
app.use((err, req, res, next) => {
  const statusCode = err.statusCode || 500;
  const message = err.message || 'Internal Server Error';
  return res.status(statusCode).json({
    success: false,
    statusCode,
    message,
  });
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
