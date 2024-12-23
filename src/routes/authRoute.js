import express from 'express';
import {
    login,
    signUp,
    verifyEmail,
    requestResetPassword,
    resetPassword,
    logout,
    getCurrentUser,
    getGoogleLoginUrl,
    handleGoogleCallback
} from '../controllers/authController.js'; 
import jwtMiddleware from '../middlewares/jwtMiddleware.js'

const router = express.Router();

router.post('/login', login);
router.post('/signup', signUp);
router.get('/verify-email', verifyEmail);
router.post('/password-reset-request', requestResetPassword);
router.post('/password-reset', resetPassword);
router.get('/logout', logout);
router.get('/current-user', jwtMiddleware, getCurrentUser);
router.get('/google-login', getGoogleLoginUrl);
router.get('/google-callback', handleGoogleCallback);


export default router;
