import { Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { OAuth2Client } from 'google-auth-library';
import pool from '../config/database';

const JWT_SECRET = process.env.JWT_SECRET || 'your_secret_key';
const GOOGLE_CLIENT_ID = '322543435047-avhj92akciptrms4sd6sqju7ipr75ru8.apps.googleusercontent.com';
const client = new OAuth2Client(GOOGLE_CLIENT_ID);

export const register = async (req: Request, res: Response): Promise<void> => {
  try {
    console.log('📝 Register request received:', { email: req.body.email, fullName: req.body.fullName });
    
    const { fullName, email, password, confirmPassword } = req.body;

    // Validate input
    if (!fullName || !email || !password || !confirmPassword) {
      console.log('❌ Missing fields');
      res.status(400).json({ 
        success: false, 
        message: 'All fields are required' 
      });
      return;
    }

    if (password !== confirmPassword) {
      console.log('❌ Passwords do not match');
      res.status(400).json({ 
        success: false, 
        message: 'Passwords do not match' 
      });
      return;
    }

    const connection = await pool.getConnection();
    console.log('✅ Database connection established');

    // Check if user already exists
    const [existingUser] = await connection.query(
      'SELECT id FROM user WHERE Email = ?',
      [email]
    );

    if ((existingUser as any[]).length > 0) {
      connection.release();
      console.log('❌ Email already exists:', email);
      res.status(409).json({ 
        success: false, 
        message: 'Email already registered' 
      });
      return;
    }

    // Hash password
    console.log('🔒 Hashing password...');
    const hashedPassword = await bcrypt.hash(password, 10);
    console.log('✅ Password hashed successfully');

    // Insert user
    await connection.query(
      'INSERT INTO user (Name, Email, Password) VALUES (?, ?, ?)',
      [fullName, email, hashedPassword]
    );
    
    console.log('✅ User inserted into database:', email);

    connection.release();

    res.status(201).json({
      success: true,
      message: 'User registered successfully'
    });
  } catch (error) {
    console.error('❌ Registration error:', error);
    console.log(error);
    res.status(500).json({ 
      success: false, 
      message: error instanceof Error ? error.message : 'Registration failed' 
    });
  }
};

export const login = async (req: Request, res: Response): Promise<void> => {
  try {
    console.log('🔐 Login request received:', { email: req.body.email });
    
    const { email, password } = req.body;

    if (!email || !password) {
      console.log('❌ Missing email or password');
      res.status(400).json({ 
        success: false, 
        message: 'Email and password are required' 
      });
      return;
    }

    const connection = await pool.getConnection();
    console.log('✅ Database connection established');

    // Find user
    const [users] = await connection.query(
      'SELECT * FROM user WHERE Email = ?',
      [email]
    );

    connection.release();

    const user = (users as any[])[0];
    if (!user) {
      console.log('❌ User not found:', email);
      res.status(401).json({ 
        success: false, 
        message: 'Invalid email or password' 
      });
      return;
    }

    // Compare password
    console.log('🔍 Comparing passwords...');
    const isPasswordValid = await bcrypt.compare(password, user.Password);
    
    if (!isPasswordValid) {
      console.log('❌ Password mismatch for user:', email);
      res.status(401).json({ 
        success: false, 
        message: 'Invalid email or password' 
      });
      return;
    }

    console.log('✅ Password matched');

    // Generate token
    console.log('🎫 Generating JWT token...');
    const token = jwt.sign(
      { id: user.id, email: user.Email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    const { Password: _, ...userWithoutPassword } = user;

    console.log('✅ Login successful for user:', email);

    res.json({
      success: true,
      message: 'Login successful',
      token,
      user: userWithoutPassword
    });
  } catch (error) {
    console.error('❌ Login error:', error);
    console.log(error);
    res.status(500).json({ 
      success: false, 
      message: error instanceof Error ? error.message : 'Login failed' 
    });
  }
};

export const googleLogin = async (req: Request, res: Response): Promise<void> => {
  try {
    console.log('🔐 Google login request received');
    const { token } = req.body;

    if (!token) {
      console.log('❌ Missing Google token');
      res.status(400).json({ 
        success: false, 
        message: 'Google token is required' 
      });
      return;
    }

    // Verify Google token
    console.log('🔍 Verifying Google token...');
    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();
    if (!payload) {
      console.log('❌ Invalid Google token');
      res.status(401).json({ 
        success: false, 
        message: 'Invalid Google token' 
      });
      return;
    }

    console.log('✅ Google token verified');
    const { email, name, picture } = payload;

    if (!email) {
      console.log('❌ Email not found in Google token');
      res.status(400).json({ 
        success: false, 
        message: 'Email not found in Google account' 
      });
      return;
    }

    const connection = await pool.getConnection();
    console.log('✅ Database connection established');

    // Check if user exists
    const [users] = await connection.query(
      'SELECT * FROM user WHERE Email = ?',
      [email]
    );

    let user = (users as any[])[0];

    if (!user) {
      // Create new user
      console.log('👤 Creating new user with Google account:', email);
      
      // Generate a temporary hashed password for Google users
      const tempPassword = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
      const hashedPassword = await bcrypt.hash(tempPassword, 10);

      await connection.query(
        'INSERT INTO user (Name, Email, Password) VALUES (?, ?, ?)',
        [name || email, email, hashedPassword]
      );

      console.log('✅ New user created via Google:', email);

      // Fetch the created user
      const [newUsers] = await connection.query(
        'SELECT * FROM user WHERE Email = ?',
        [email]
      );
      user = (newUsers as any[])[0];
    } else {
      console.log('✅ Existing user found:', email);
    }

    connection.release();

    // Generate JWT token
    console.log('🎫 Generating JWT token...');
    const jwtToken = jwt.sign(
      { id: user.id, email: user.Email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    const { Password: _, ...userWithoutPassword } = user;

    console.log('✅ Google login successful for user:', email);

    res.json({
      success: true,
      message: 'Google login successful',
      token: jwtToken,
      user: userWithoutPassword
    });
  } catch (error) {
    console.error('❌ Google login error:', error);
    res.status(500).json({ 
      success: false, 
      message: error instanceof Error ? error.message : 'Google login failed' 
    });
  }
};
