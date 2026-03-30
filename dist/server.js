"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const cors_1 = __importDefault(require("cors"));
const dotenv_1 = __importDefault(require("dotenv"));
const auth_1 = __importDefault(require("./routes/auth"));
const database_1 = __importDefault(require("./config/database"));
dotenv_1.default.config();
const app = (0, express_1.default)();
// Middleware
app.use((0, cors_1.default)({
    origin: 'http://localhost:5173', // Your React app URL
    credentials: true
}));
app.use(express_1.default.json());
// Routes
app.use('/api/auth', auth_1.default);
// Health check
app.get('/api/health', (req, res) => {
    res.json({ status: 'Server is running' });
});
// Database test
app.get('/api/db-test', async (req, res) => {
    try {
        const connection = await database_1.default.getConnection();
        const [result] = await connection.query('SELECT 1');
        connection.release();
        res.json({
            success: true,
            message: 'Database connected successfully',
            database: process.env.DB_NAME,
            host: process.env.DB_HOST
        });
    }
    catch (error) {
        console.error('Database test error:', error);
        res.status(500).json({
            success: false,
            message: error instanceof Error ? error.message : 'Database connection failed',
            database: process.env.DB_NAME,
            host: process.env.DB_HOST
        });
    }
});
// Error handling
app.use((err, req, res, next) => {
    console.error('Server error:', err);
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
});
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
    console.log(`📡 CORS enabled for http://localhost:5173`);
    console.log(`📊 Database: ${process.env.DB_NAME}`);
    console.log(`🔌 Database Host: ${process.env.DB_HOST}`);
});
//# sourceMappingURL=server.js.map