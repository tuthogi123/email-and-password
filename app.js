const express = require('express');
const session = require('express-session');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const dotenv = require("dotenv")
require('dotenv').config();
const crypto = require('crypto');
const bodyParser = require('body-parser');
const app = express();

app.use(bodyParser.json());

const generateSecretKey = () => {
    const secretKey = crypto.randomBytes(8).toString('hex');
    return secretKey;
  };
// Initialize Express app
const port = process.env.PORT || 3000;

// Set up session middleware
app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: false
}));

// Set up database connection
// mongoose.connect('mongodb://localhost:27017/myapp', {
//   useNewUrlParser: true,
//   useUnifiedTopology: true,
//   useCreateIndex: true
// }).then(() => {
//   console.log('Connected to database');
// }).catch((error) => {
//   console.error('Database connection error:', error);
// });

// Define User schema and model
const UserSchema = new mongoose.Schema({
  email: { type: String, unique: true },
  password: String,
  isVerified: { type: Boolean, default: false },
  verificationToken: String,
  resetToken: String,
  resetTokenExpiration: Date
});

const users = [
    {"email":"evanskarani076@gmail.com","password":"112233"}
];
app.get("/api/users",(req,res)=>{
    res.send(users);
})
const User = mongoose.model('User', UserSchema);

// Set up email transporter
const transporter = nodemailer.createTransport({
  service: 'your-email-service',
  auth: {
    user: 'your-email',
    pass: 'your-email-password'
  }
});

// Other required configurations and routes...
app.post('/api/signup', async (req, res) => {
    const { email, password } = req.body;
  
    try {
      // Check if email already exists
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(400).json({ message: 'Email already registered' });
      }
  
      // Generate verification token
      const verificationToken = Math.random().toString(36).substring(7);
      
      // Hash the password
      const hashedPassword = await bcrypt.hash(password, 10);
  
      // Create new user
      const newUser = new User({
        email,
        password: hashedPassword,
        verificationToken
      });
      await newUser.save();
  
      // Send verification email
      const mailOptions = {
        from: 'your-email',
        to: email,
        subject: 'Email Verification',
        text: `Click the following link to verify your email: http://localhost:3000/verify/${verificationToken}`
      };
  
      await transporter.sendMail(mailOptions);
  
      res.status(200).json({ message: 'Please check your email for verification' });
    } catch (error) {
      console.error('Sign up error:', error);
      res.status(500).json({ message: 'Internal server error' });
    }
  });
  app.get('/api/verify/:token', async (req, res) => {
    const { token } = req.params;
  
    try {
      // Find the user with the given verification token
      const user = await User.findOne({ verificationToken: token });
      if (!user) {
        return res.status(400).json({ message: 'Invalid verification token' });
      }
  
      // Mark the user as verified
      user.isVerified = true;
      user.verificationToken = '';
      await user.save();
  
      res.status(200).json({ message: 'Email verified successfully' });
    } catch (error) {
      console.error('Email verification error:', error);
      res.status(500).json({ message: 'Internal server error' });
    }
  });
  app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
  
    try {
      // Find the user with the given email
      const user = await User.findOne({ email });
      if (!user) {
        return res.status(400).json({ message: 'Invalid email or password' });
      }
  
      // Check if the password is correct
      const passwordMatch = await bcrypt.compare(password, user.password);
      if (!passwordMatch) {
        return res.status(400).json({ message: 'Invalid email or password' });
      }
  
      // Check if the email is verified
      if (!user.isVerified) {
        return res.status(400).json({ message: 'Email not verified' });
      }
  
      // Set the user's session or issue a JWT for authentication
      req.session.userId = user._id;
  
      res.status(200).json({ message: 'Logged in successfully' });
    } catch (error) {
      console.error('Login error:', error);
      res.status(500).json({ message: 'Internal server error' });
    }
  });
  
  app.post('/api/reset', async (req, res) => {
    const { email } = req.body;
  
    try {
      // Find the user with the given email
      const user = await User.findOne({ email });
      if (!user) {
        return res.status(400).json({ message: 'Email not registered' });
      }
  
      // Generate reset token and expiration date
      const resetToken = Math.random().toString(36).substring(7);
      const resetTokenExpiration = new Date(Date.now() + 3600000); // 1 hour
  
      // Update the user with the reset token and expiration date
      user.resetToken = resetToken;
      user.resetTokenExpiration = resetTokenExpiration;
      await user.save();
  
      // Send password reset email
      const mailOptions = {
        from: 'your-email',
        to: email,
        subject: 'Password Reset',
        text: `Click the following link to reset your password: http://localhost:3000/reset/${resetToken}`
      };
  
      await transporter.sendMail(mailOptions);
  
      res.status(200).json({ message: 'Please check your email for password reset instructions' });
    } catch (error) {
      console.error('Password reset error:', error);
      res.status(500).json({ message: 'Internal server error' });
    }
  });
  app.post('/reset/:token', async (req, res) => {
    const { token } = req.params;
    const { password } = req.body;
  
    try {
      // Find the user with the given reset token
      const user = await User.findOne({ resetToken: token, resetTokenExpiration: { $gt: Date.now() } });
      if (!user) {
        return res.status(400).json({ message: 'Invalid or expired reset token' });
      }
  
      // Hash the new password
      const hashedPassword = await bcrypt.hash(password, 10);
  
      // Update the user with the new password and reset token
      user.password = hashedPassword;
      user.resetToken = '';
      user.resetTokenExpiration = null;
      await user.save();
  
      res.status(200).json({ message: 'Password reset successfully' });
    } catch (error) {
      console.error('Password update error:', error);
      res.status(500).json({ message: 'Internal server error' });
    }
  });
  const connectToMongoDB = async () => {
    try {
      await mongoose.connect(process.env.DB_CONNECTION, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
      });
      console.log('Connected to MongoDB Atlas');
      app.listen(port, () => {
        console.log(`Server is listening on port ${port}`);
      });
    } catch (error) {
      console.error('Error connecting to MongoDB Atlas:', error);
      process.exit(1); // Exit the process if unable to connect to the database
    }
  };
  
  connectToMongoDB(); 

// Start the server
app.listen( () => {
  console.log('Server started on port 3000');
});
