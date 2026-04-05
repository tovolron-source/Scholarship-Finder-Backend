import { Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { OAuth2Client } from 'google-auth-library';
import pool from '../config/database';

const JWT_SECRET = process.env.JWT_SECRET || 'your_secret_key';
const GOOGLE_CLIENT_ID = '322543435047-avhj92akciptrms4sd6sqju7ipr75ru8.apps.googleusercontent.com';
const client = new OAuth2Client(GOOGLE_CLIENT_ID);

export const getUserById = async (req: Request, res: Response): Promise<void> => {
  try {
    const userId = req.params.id;

    if (!userId) {
      res.status(400).json({
        success: false,
        message: 'User ID is required'
      });
      return;
    }

    const connection = await pool.getConnection();
    const [users] = await connection.query(
      'SELECT u.id, u.FullName, u.Email, u.Name, sp.gender, sp.address, sp.contactNumber, sp.profilePhoto, sp.profileCompletion, sp.school, sp.course, sp.yearLevel, sp.gpa, sp.financialStatus FROM user u LEFT JOIN student_profile sp ON u.id = sp.userId WHERE u.id = ?',
      [userId]
    );
    connection.release();

    const user = (users as any[])[0];
    if (!user) {
      res.status(404).json({
        success: false,
        message: 'User not found'
      });
      return;
    }

    res.json({
      success: true,
      user
    });
  } catch (error) {
    console.error('Error fetching user:', error);
    res.status(500).json({
      success: false,
      message: error instanceof Error ? error.message : 'Failed to fetch user'
    });
  }
};

// Helper function to create or update student profile
const createOrUpdateStudentProfile = async (connection: any, userId: number, gender?: string, address?: string, school?: string, course?: string, yearLevel?: string, gpa?: number, financialStatus?: string, contactNumber?: string, profilePhoto?: string, profileCompletion?: number): Promise<void> => {
  try {
    // Check if student profile exists
    const [existingProfileRows] = await connection.query(
      'SELECT * FROM student_profile WHERE userId = ?',
      [userId]
    );

    const existingProfile = (existingProfileRows as any[])[0];

    if (existingProfile) {
      const updatedGender = gender !== undefined ? gender : existingProfile.gender;
      const updatedAddress = address !== undefined ? address : existingProfile.address;
      const updatedSchool = school !== undefined ? school : existingProfile.school;
      const updatedCourse = course !== undefined ? course : existingProfile.course;
      const updatedYearLevel = yearLevel !== undefined ? yearLevel : existingProfile.yearLevel;
      const updatedGpa = typeof gpa === 'number' && Number.isFinite(gpa) ? gpa : existingProfile.gpa;
      const updatedFinancialStatus = financialStatus !== undefined ? financialStatus : existingProfile.financialStatus;
      const updatedContactNumber = contactNumber !== undefined ? contactNumber : existingProfile.contactNumber;
      const updatedProfilePhoto = profilePhoto !== undefined ? profilePhoto : existingProfile.profilePhoto;
      const updatedProfileCompletion = profileCompletion !== undefined ? profileCompletion : existingProfile.profileCompletion;

      await connection.query(
        `UPDATE student_profile SET
          gender = ?, address = ?, school = ?, course = ?, yearLevel = ?, gpa = ?, financialStatus = ?, contactNumber = ?, profilePhoto = ?, profileCompletion = ?
        WHERE userId = ?`,
        [
          updatedGender,
          updatedAddress,
          updatedSchool,
          updatedCourse,
          updatedYearLevel,
          updatedGpa,
          updatedFinancialStatus,
          updatedContactNumber,
          updatedProfilePhoto,
          updatedProfileCompletion,
          userId
        ]
      );
    } else {
      await connection.query(
        `INSERT INTO student_profile (userId, gender, address, school, course, yearLevel, gpa, financialStatus, contactNumber, profilePhoto, profileCompletion)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [userId, gender, address, school, course, yearLevel, typeof gpa === 'number' && Number.isFinite(gpa) ? gpa : null, financialStatus, contactNumber, profilePhoto, profileCompletion]
      );
    }
  } catch (error) {
    console.error('Error creating/updating student profile:', error);
    throw error;
  }
};

export const updateUser = async (req: Request, res: Response): Promise<void> => {
  try {
    const userId = req.params.id;
    const { fullName, email, gender, address, contactNumber, school, course, yearLevel, financialStatus, profilePhoto, profileCompletion } = req.body;
    let gpa: number | undefined;

    if (req.body.gpa !== undefined && req.body.gpa !== null) {
      const parsedGpa = Number(req.body.gpa);
      gpa = Number.isFinite(parsedGpa) ? parsedGpa : undefined;
    }

    if (!userId) {
      res.status(400).json({
        success: false,
        message: 'User ID is required'
      });
      return;
    }

    const connection = await pool.getConnection();

    if (email !== undefined) {
      const [existingEmailRows] = await connection.query(
        'SELECT id FROM user WHERE Email = ? AND id <> ?',
        [email, userId]
      );
      if ((existingEmailRows as any[]).length > 0) {
        connection.release();
        res.status(409).json({
          success: false,
          message: 'Email is already in use'
        });
        return;
      }
    }

    const updateFields: string[] = [];
    const updateValues: any[] = [];

    if (fullName !== undefined) {
      updateFields.push('Name = ?', 'FullName = ?');
      updateValues.push(fullName, fullName);
    }

    if (email !== undefined) {
      updateFields.push('Email = ?');
      updateValues.push(email);
    }

    if (updateFields.length > 0) {
      await connection.query(
        `UPDATE user SET ${updateFields.join(', ')} WHERE id = ?`,
        [...updateValues, userId]
      );
    }

    // Update or create student profile with all profile information
    await createOrUpdateStudentProfile(
      connection,
      parseInt(userId),
      gender,
      address,
      school,
      course,
      yearLevel,
      gpa,
      financialStatus,
      contactNumber,
      profilePhoto,
      profileCompletion
    );

    const [updatedUsers] = await connection.query(
      'SELECT u.id, u.FullName, u.Email, u.Name, sp.gender, sp.address, sp.contactNumber, sp.profilePhoto, sp.profileCompletion, sp.school, sp.course, sp.yearLevel, sp.gpa, sp.financialStatus FROM user u LEFT JOIN student_profile sp ON u.id = sp.userId WHERE u.id = ?',
      [userId]
    );
    connection.release();

    const updatedUser = (updatedUsers as any[])[0];

    res.json({
      success: true,
      message: 'User updated successfully',
      user: updatedUser
    });
  } catch (error) {
    console.error('Error updating user:', error);
    res.status(500).json({
      success: false,
      message: error instanceof Error ? error.message : 'Failed to update user'
    });
  }
};

export const uploadProfilePhoto = async (req: Request, res: Response): Promise<void> => {
  try {
    const userId = req.params.userId;

    if (!userId) {
      res.status(400).json({
        success: false,
        message: 'User ID is required'
      });
      return;
    }

    if (!req.file) {
      res.status(400).json({
        success: false,
        message: 'No file uploaded'
      });
      return;
    }

    const profilePhotoPath = `/uploads/${req.file.filename}`;

    const connection = await pool.getConnection();

    // Update or create student profile with the profile photo
    await createOrUpdateStudentProfile(
      connection,
      parseInt(userId),
      undefined, // school
      undefined, // course
      undefined, // yearLevel
      undefined, // gpa
      undefined, // financialStatus
      undefined, // contactNumber
      profilePhotoPath, // profilePhoto
      undefined // profileCompletion
    );

    connection.release();

    res.json({
      success: true,
      message: 'Profile photo uploaded successfully',
      profilePhoto: profilePhotoPath
    });
  } catch (error) {
    console.error('Error uploading profile photo:', error);
    res.status(500).json({
      success: false,
      message: error instanceof Error ? error.message : 'Failed to upload profile photo'
    });
  }
};

export const getStudentProfile = async (req: Request, res: Response): Promise<void> => {
  try {
    const userId = req.params.userId;

    if (!userId) {
      res.status(400).json({
        success: false,
        message: 'User ID is required'
      });
      return;
    }

    const connection = await pool.getConnection();
    const [profiles] = await connection.query(
      'SELECT * FROM student_profile WHERE userId = ?',
      [userId]
    );
    connection.release();

    const profile = (profiles as any[])[0];

    if (!profile) {
      res.status(404).json({
        success: false,
        message: 'Student profile not found',
        profile: null
      });
      return;
    }

    res.json({
      success: true,
      message: 'Student profile retrieved successfully',
      profile
    });
  } catch (error) {
    console.error('Error fetching student profile:', error);
    res.status(500).json({
      success: false,
      message: error instanceof Error ? error.message : 'Failed to fetch student profile'
    });
  }
};

export const register = async (req: Request, res: Response): Promise<void> => {
  try {
    console.log('Register request received:', { email: req.body.email, fullName: req.body.fullName });
    
    const { fullName, email, password, confirmPassword } = req.body;

    // Validate input
    if (!fullName || !email || !password || !confirmPassword) {
      console.log('Missing fields');
      res.status(400).json({ 
        success: false, 
        message: 'All fields are required' 
      });
      return;
    }

    if (password !== confirmPassword) {
      console.log('Passwords do not match');
      res.status(400).json({ 
        success: false, 
        message: 'Passwords do not match' 
      });
      return;
    }

    const connection = await pool.getConnection();
    console.log('Database connection established');

    // Check if user already exists
    const [existingUser] = await connection.query(
      'SELECT id FROM user WHERE Email = ?',
      [email]
    );

    if ((existingUser as any[]).length > 0) {
      connection.release();
      console.log('Email already exists:', email);
      res.status(409).json({ 
        success: false, 
        message: 'Email already registered' 
      });
      return;
    }

    // Hash password
    console.log('Hashing password...');
    const hashedPassword = await bcrypt.hash(password, 10);
    console.log('Password hashed successfully');

    // Insert user
    const [result] = await connection.query(
      'INSERT INTO user (Name, Email, Password, FullName) VALUES (?, ?, ?, ?)',
      [fullName, email, hashedPassword, fullName]
    );

    const insertId = (result as any).insertId;
    console.log('User inserted into database:', email, 'id:', insertId);

    // Create initial student profile record
    await connection.query(
      'INSERT INTO student_profile (userId, profileCompletion) VALUES (?, ?)',
      [insertId, 20]
    );

    connection.release();

    // Generate token
    const token = jwt.sign(
      { id: insertId, email: email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    // Fetch the created user to return complete data
    const newConnection = await pool.getConnection();
    const [registeredUsers] = await newConnection.query(
      'SELECT u.id, u.FullName, u.Email, u.Name, sp.gender, sp.address, sp.contactNumber, sp.profilePhoto, sp.profileCompletion, sp.school, sp.course, sp.yearLevel, sp.gpa, sp.financialStatus FROM user u LEFT JOIN student_profile sp ON u.id = sp.userId WHERE u.Email = ?',
      [email]
    );
    newConnection.release();

    const registeredUser = (registeredUsers as any[])[0];

    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      token,
      user: registeredUser
    });
  } catch (error) {
    console.error('Registration error:', error);
    console.log(error);
    res.status(500).json({ 
      success: false, 
      message: error instanceof Error ? error.message : 'Registration failed' 
    });
  }
};

export const login = async (req: Request, res: Response): Promise<void> => {
  try {
    console.log('Login request received:', { email: req.body.email });
    
    const { email, password } = req.body;

    if (!email || !password) {
      console.log('Missing email or password');
      res.status(400).json({ 
        success: false, 
        message: 'Email and password are required' 
      });
      return;
    }

    const connection = await pool.getConnection();
    console.log('Database connection established');

    // Find user with profile data
    const [users] = await connection.query(
      'SELECT u.*, sp.gender, sp.address, sp.contactNumber, sp.profilePhoto, sp.profileCompletion, sp.school, sp.course, sp.yearLevel, sp.gpa, sp.financialStatus FROM user u LEFT JOIN student_profile sp ON u.id = sp.userId WHERE u.Email = ?',
      [email]
    );

    connection.release();

    const user = (users as any[])[0];
    if (!user) {
      console.log('User not found:', email);
      res.status(401).json({ 
        success: false, 
        message: 'Invalid email or password' 
      });
      return;
    }

    // Compare password
    console.log('Comparing passwords...');
    const isPasswordValid = await bcrypt.compare(password, user.Password);
    
    if (!isPasswordValid) {
      console.log('Password mismatch for user:', email);
      res.status(401).json({ 
        success: false, 
        message: 'Invalid email or password' 
      });
      return;
    }

    console.log('Password matched');

    // Generate token
    console.log('Generating JWT token...');
    const token = jwt.sign(
      { id: user.id, email: user.Email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    const { Password: _, ...userWithoutPassword } = user;

    console.log('Login successful for user:', email);

    res.json({
      success: true,
      message: 'Login successful',
      token,
      user: userWithoutPassword
    });
  } catch (error) {
    console.error('Login error:', error);
    console.log(error);
    res.status(500).json({ 
      success: false, 
      message: error instanceof Error ? error.message : 'Login failed' 
    });
  }
};

export const googleLogin = async (req: Request, res: Response): Promise<void> => {
  try {
    console.log('Google login request received');
    const { token } = req.body;

    if (!token) {
      console.log('Missing Google token');
      res.status(400).json({ 
        success: false, 
        message: 'Google token is required' 
      });
      return;
    }

    // Verify Google token
    console.log('Verifying Google token...');
    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();
    if (!payload) {
      console.log('Invalid Google token');
      res.status(401).json({ 
        success: false, 
        message: 'Invalid Google token' 
      });
      return;
    }

    console.log('Google token verified');
    const { email, name, picture } = payload;

    if (!email) {
      console.log('Email not found in Google token');
      res.status(400).json({ 
        success: false, 
        message: 'Email not found in Google account' 
      });
      return;
    }

    const connection = await pool.getConnection();
    console.log('Database connection established');

    // Check if user exists
    const [users] = await connection.query(
      'SELECT * FROM user WHERE Email = ?',
      [email]
    );

    let user = (users as any[])[0];

    if (!user) {
      // Create new user
      console.log('Creating new user with Google account:', email);
      
      // Generate a temporary hashed password for Google users
      const tempPassword = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
      const hashedPassword = await bcrypt.hash(tempPassword, 10);

      await connection.query(
        'INSERT INTO user (Name, Email, Password) VALUES (?, ?, ?)',
        [name || email, email, hashedPassword]
      );

      console.log('New user created via Google:', email);

      // Fetch the created user
      const [newUsers] = await connection.query(
        'SELECT * FROM user WHERE Email = ?',
        [email]
      );
      user = (newUsers as any[])[0];
    } else {
      console.log('Existing user found:', email);
    }

    connection.release();

    // Generate JWT token
    console.log('Generating JWT token...');
    const jwtToken = jwt.sign(
      { id: user.id, email: user.Email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    const { Password: _, ...userWithoutPassword } = user;

    console.log('Google login successful for user:', email);

    res.json({
      success: true,
      message: 'Google login successful',
      token: jwtToken,
      user: userWithoutPassword
    });
  } catch (error) {
    console.error('Google login error:', error);
    res.status(500).json({ 
      success: false, 
      message: error instanceof Error ? error.message : 'Google login failed' 
    });
  }
};
