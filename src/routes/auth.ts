import { Router } from 'express';
import multer from 'multer';
import path from 'path';
import { register, login, googleLogin, getUserById, updateUser, getStudentProfile, uploadProfilePhoto } from '../controllers/authController';
import { verifyToken } from '../middleware/auth';

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, path.join(__dirname, '../../uploads'));
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, 'profile-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
  },
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);

    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb(new Error('Only image files are allowed!'));
    }
  }
});

const router = Router();

router.post('/register', register);
router.post('/login', login);
router.post('/google', googleLogin);
router.get('/user/:id', verifyToken, getUserById);
router.put('/user/:id', verifyToken, updateUser);
router.post('/upload-profile-photo/:userId', verifyToken, upload.single('profilePhoto'), uploadProfilePhoto);
router.get('/student-profile/:userId', verifyToken, getStudentProfile);

export default router;
