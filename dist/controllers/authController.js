"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.googleLogin = exports.login = exports.register = exports.getStudentProfile = exports.uploadProfilePhoto = exports.updateUser = exports.getUserById = void 0;
const bcryptjs_1 = __importDefault(require("bcryptjs"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const google_auth_library_1 = require("google-auth-library");
const database_1 = __importDefault(require("../config/database"));
const JWT_SECRET = process.env.JWT_SECRET || 'your_secret_key';
const GOOGLE_CLIENT_ID = '322543435047-avhj92akciptrms4sd6sqju7ipr75ru8.apps.googleusercontent.com';
const client = new google_auth_library_1.OAuth2Client(GOOGLE_CLIENT_ID);
const getUserById = async (req, res) => {
    try {
        const userId = req.params.id;
        if (!userId) {
            res.status(400).json({
                success: false,
                message: 'User ID is required'
            });
            return;
        }
        const connection = await database_1.default.getConnection();
        const [users] = await connection.query('SELECT u.id, u.FullName, u.Email, u.Name, sp.contactNumber, sp.profilePhoto, sp.profileCompletion, sp.school, sp.course, sp.yearLevel, sp.gpa, sp.financialStatus FROM user u LEFT JOIN student_profile sp ON u.id = sp.userId WHERE u.id = ?', [userId]);
        connection.release();
        const user = users[0];
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
    }
    catch (error) {
        console.error('Error fetching user:', error);
        res.status(500).json({
            success: false,
            message: error instanceof Error ? error.message : 'Failed to fetch user'
        });
    }
};
exports.getUserById = getUserById;
// Helper function to create or update student profile
const createOrUpdateStudentProfile = async (connection, userId, school, course, yearLevel, gpa, financialStatus, contactNumber, profilePhoto, profileCompletion) => {
    try {
        // Check if student profile exists
        const [existingProfile] = await connection.query('SELECT id FROM student_profile WHERE userId = ?', [userId]);
        if (existingProfile.length > 0) {
            // Update existing profile
            await connection.query(`UPDATE student_profile SET
          school = ?, course = ?, yearLevel = ?, gpa = ?, financialStatus = ?, contactNumber = ?, profilePhoto = ?, profileCompletion = ?
        WHERE userId = ?`, [school, course, yearLevel, gpa, financialStatus, contactNumber, profilePhoto, profileCompletion, userId]);
        }
        else {
            // Create new student profile
            await connection.query(`INSERT INTO student_profile (userId, school, course, yearLevel, gpa, financialStatus, contactNumber, profilePhoto, profileCompletion)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, [userId, school, course, yearLevel, gpa, financialStatus, contactNumber, profilePhoto, profileCompletion]);
        }
    }
    catch (error) {
        console.error('Error creating/updating student profile:', error);
        throw error;
    }
};
const updateUser = async (req, res) => {
    try {
        const userId = req.params.id;
        const { fullName, contactNumber, school, course, yearLevel, gpa, financialStatus, profilePhoto, profileCompletion } = req.body;
        if (!userId) {
            res.status(400).json({
                success: false,
                message: 'User ID is required'
            });
            return;
        }
        const connection = await database_1.default.getConnection();
        // Update basic user information in user table
        await connection.query(`UPDATE user SET
        Name = ?, FullName = ?
      WHERE id = ?`, [fullName, fullName, userId]);
        // Update or create student profile with all profile information
        await createOrUpdateStudentProfile(connection, parseInt(userId), school, course, yearLevel, gpa, financialStatus, contactNumber, profilePhoto, profileCompletion);
        const [updatedUsers] = await connection.query('SELECT u.id, u.FullName, u.Email, u.Name, sp.contactNumber, sp.profilePhoto, sp.profileCompletion, sp.school, sp.course, sp.yearLevel, sp.gpa, sp.financialStatus FROM user u LEFT JOIN student_profile sp ON u.id = sp.userId WHERE u.id = ?', [userId]);
        connection.release();
        const updatedUser = updatedUsers[0];
        res.json({
            success: true,
            message: 'User updated successfully',
            user: updatedUser
        });
    }
    catch (error) {
        console.error('Error updating user:', error);
        res.status(500).json({
            success: false,
            message: error instanceof Error ? error.message : 'Failed to update user'
        });
    }
};
exports.updateUser = updateUser;
const uploadProfilePhoto = async (req, res) => {
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
        const connection = await database_1.default.getConnection();
        // Update or create student profile with the profile photo
        await createOrUpdateStudentProfile(connection, parseInt(userId), undefined, // school
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
    }
    catch (error) {
        console.error('Error uploading profile photo:', error);
        res.status(500).json({
            success: false,
            message: error instanceof Error ? error.message : 'Failed to upload profile photo'
        });
    }
};
exports.uploadProfilePhoto = uploadProfilePhoto;
const getStudentProfile = async (req, res) => {
    try {
        const userId = req.params.userId;
        if (!userId) {
            res.status(400).json({
                success: false,
                message: 'User ID is required'
            });
            return;
        }
        const connection = await database_1.default.getConnection();
        const [profiles] = await connection.query('SELECT * FROM student_profile WHERE userId = ?', [userId]);
        connection.release();
        const profile = profiles[0];
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
    }
    catch (error) {
        console.error('Error fetching student profile:', error);
        res.status(500).json({
            success: false,
            message: error instanceof Error ? error.message : 'Failed to fetch student profile'
        });
    }
};
exports.getStudentProfile = getStudentProfile;
const register = async (req, res) => {
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
        const connection = await database_1.default.getConnection();
        console.log('Database connection established');
        // Check if user already exists
        const [existingUser] = await connection.query('SELECT id FROM user WHERE Email = ?', [email]);
        if (existingUser.length > 0) {
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
        const hashedPassword = await bcryptjs_1.default.hash(password, 10);
        console.log('Password hashed successfully');
        // Insert user
        await connection.query('INSERT INTO user (Name, Email, Password, FullName, ProfileCompletion) VALUES (?, ?, ?, ?, ?)', [fullName, email, hashedPassword, fullName, 20]);
        console.log('User inserted into database:', email);
        connection.release();
        // Generate token
        const token = jsonwebtoken_1.default.sign({ id: 0, email: email }, JWT_SECRET, { expiresIn: '7d' });
        // Fetch the created user to return complete data
        const newConnection = await database_1.default.getConnection();
        const [registeredUsers] = await newConnection.query('SELECT id, FullName, Email, Name, ProfileCompletion FROM user WHERE Email = ?', [email]);
        newConnection.release();
        const registeredUser = registeredUsers[0];
        res.status(201).json({
            success: true,
            message: 'User registered successfully',
            token,
            user: registeredUser
        });
    }
    catch (error) {
        console.error('Registration error:', error);
        console.log(error);
        res.status(500).json({
            success: false,
            message: error instanceof Error ? error.message : 'Registration failed'
        });
    }
};
exports.register = register;
const login = async (req, res) => {
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
        const connection = await database_1.default.getConnection();
        console.log('Database connection established');
        // Find user
        const [users] = await connection.query('SELECT * FROM user WHERE Email = ?', [email]);
        connection.release();
        const user = users[0];
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
        const isPasswordValid = await bcryptjs_1.default.compare(password, user.Password);
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
        const token = jsonwebtoken_1.default.sign({ id: user.id, email: user.Email }, JWT_SECRET, { expiresIn: '7d' });
        const { Password: _, ...userWithoutPassword } = user;
        console.log('Login successful for user:', email);
        res.json({
            success: true,
            message: 'Login successful',
            token,
            user: userWithoutPassword
        });
    }
    catch (error) {
        console.error('Login error:', error);
        console.log(error);
        res.status(500).json({
            success: false,
            message: error instanceof Error ? error.message : 'Login failed'
        });
    }
};
exports.login = login;
const googleLogin = async (req, res) => {
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
        const connection = await database_1.default.getConnection();
        console.log('Database connection established');
        // Check if user exists
        const [users] = await connection.query('SELECT * FROM user WHERE Email = ?', [email]);
        let user = users[0];
        if (!user) {
            // Create new user
            console.log('Creating new user with Google account:', email);
            // Generate a temporary hashed password for Google users
            const tempPassword = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
            const hashedPassword = await bcryptjs_1.default.hash(tempPassword, 10);
            await connection.query('INSERT INTO user (Name, Email, Password) VALUES (?, ?, ?)', [name || email, email, hashedPassword]);
            console.log('New user created via Google:', email);
            // Fetch the created user
            const [newUsers] = await connection.query('SELECT * FROM user WHERE Email = ?', [email]);
            user = newUsers[0];
        }
        else {
            console.log('Existing user found:', email);
        }
        connection.release();
        // Generate JWT token
        console.log('Generating JWT token...');
        const jwtToken = jsonwebtoken_1.default.sign({ id: user.id, email: user.Email }, JWT_SECRET, { expiresIn: '7d' });
        const { Password: _, ...userWithoutPassword } = user;
        console.log('Google login successful for user:', email);
        res.json({
            success: true,
            message: 'Google login successful',
            token: jwtToken,
            user: userWithoutPassword
        });
    }
    catch (error) {
        console.error('Google login error:', error);
        res.status(500).json({
            success: false,
            message: error instanceof Error ? error.message : 'Google login failed'
        });
    }
};
exports.googleLogin = googleLogin;
//# sourceMappingURL=authController.js.map