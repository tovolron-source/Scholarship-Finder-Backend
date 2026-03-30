import { Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import pool from '../config/database';

const JWT_SECRET = process.env.JWT_SECRET || 'your_secret_key';

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
