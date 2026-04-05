"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const promise_1 = __importDefault(require("mysql2/promise"));
const dotenv_1 = __importDefault(require("dotenv"));
dotenv_1.default.config();
const pool = promise_1.default.createPool({
    host: process.env.DB_HOST,
    port: parseInt(process.env.DB_PORT || '3306'),
    database: process.env.DB_NAME,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD || '',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
});
// Initialize database tables on startup
async function initializeTables() {
    try {
        const connection = await pool.getConnection();
        console.log('📊 Initializing database tables...');
        // Create users table if it doesn't exist
        await connection.query(`
      CREATE TABLE IF NOT EXISTS user (
        id INT AUTO_INCREMENT PRIMARY KEY,
        Name VARCHAR(255) NOT NULL,
        FullName VARCHAR(255),
        Email VARCHAR(255) UNIQUE NOT NULL,
        Password VARCHAR(255) NOT NULL,
        RegistrationDate TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
        console.log('✅ Users table ready');
        // Create student_profile table if it doesn't exist
        await connection.query(`
      CREATE TABLE IF NOT EXISTS student_profile (
        id INT AUTO_INCREMENT PRIMARY KEY,
        userId INT NOT NULL UNIQUE,
        school VARCHAR(255),
        course VARCHAR(255),
        yearLevel VARCHAR(50),
        gpa DECIMAL(3,2),
        financialStatus VARCHAR(50),
        contactNumber VARCHAR(20),
        profilePhoto VARCHAR(500),
        profileCompletion INT DEFAULT 20,
        createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (userId) REFERENCES user(id) ON DELETE CASCADE
      )
    `);
        console.log('✅ Student Profile table ready');
        connection.release();
    }
    catch (error) {
        console.error('❌ Error initializing tables:', error);
        throw error;
    }
}
// Initialize on import
initializeTables().catch(err => {
    console.error('❌ Failed to initialize database:', err.message);
    process.exit(1);
});
exports.default = pool;
//# sourceMappingURL=database.js.map