import mysql from 'mysql2/promise';
import dotenv from 'dotenv';

dotenv.config();

const pool = mysql.createPool({
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
        Email VARCHAR(255) UNIQUE NOT NULL,
        Password VARCHAR(255) NOT NULL,
        RegistrationDate TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    console.log('✅ Users table ready');
    connection.release();
  } catch (error) {
    console.error('❌ Error initializing tables:', error);
    throw error;
  }
}

// Initialize on import
initializeTables().catch(err => {
  console.error('❌ Failed to initialize database:', err.message);
  process.exit(1);
});

export default pool;
