import { Instructor, Student, User } from '../models/userModel.js';
import bcrypt from 'bcrypt'
import UnauthorizedError from '../errors/unauthorizedError.js'
import BadRequestError from '../errors/badRequestError.js'
import ForbiddenError from '../errors/forbiddenError.js';
import jwtServices from '../utils/jwtServices.js';
import nodemailer from 'nodemailer';
import dotenv from 'dotenv'
import NotFoundError from '../errors/badRequestError.js';
import crypto from 'crypto'
import { ROLES } from '../models/roles.js';
import { promisify } from 'util';
import Joi from 'joi';
import querystring from 'querystring';
import axios from 'axios';



dotenv.config()

const BASE_FE_URL = "http://localhost:3000"

// Login by email and password
export const login = async (req, res, next) => {
    try {
        const { email, password } = req.body;

        // Validate the body
        const bodySchema = Joi.object({
            email: Joi.string().email().required(),
            password: Joi.string().min(6).required()
        });

        const { error } = bodySchema.validate(req.body);
        if (error) {
            throw error;
        }

        const user = await User.findOne({ email: email }).select('+password').lean();
        // User with this email doesn't exist
        if (!user) {
            throw new UnauthorizedError("Email or password is incorrect");
        };

        // User is disbled
        if (!user.status) {
            throw new ForbiddenError("This user is disabled");
        };

        // Email not activated yet
        if (!user.isVerified) {
            throw new ForbiddenError("This account hasn't been verifed yet");
        }

        const validPassword = await bcrypt.compare(password, user.password);
        // Password is not match
        if (!validPassword) {
            throw new UnauthorizedError("Email or password is incorrect");
        };

        await setTokenInCookie(user, res);

        res.status(200).send({
            user_id: user._id,
            role: user.role
        });

    } catch (error) {
        next(error)
    };
};

const setTokenInCookie = async (user, res) => {
    const payload = {
        user_id: user._id,
        role: user.role,
        email: user.email,
    };

    const accessToken = jwtServices.generateAccessToken(payload);
    const refreshToken = jwtServices.generateRefreshToken(null, payload);

    // Update refresh token of user with the new one
    await User.findOneAndUpdate(
        { email: user.email },
        { refreshToken: refreshToken },
    );

    // Set tokens in cookies
    res.cookie('access_token', accessToken, {
        httpOnly: true,
        sameSite: 'Strict',
        path: '/api',
        maxAge: 1000 * 60 * 30, // 30 minutes
    });

    res.cookie('refresh_token', refreshToken, {
        httpOnly: true,
        sameSite: 'Strict',
        path: '/api/auth/refresh',
        maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
    });
};


export const signUp = async (req, res, next) => {
    try {
        const { role, ...userData } = req.body;

        const bodySchema = Joi.object({
            fullName: Joi.string().max(100).required(),
            birthDate: Joi.date().less('now').required().messages({
                'date.base': 'Birthdate must be in format YYYY-MM-DDThh:mmZ.',
                'date.less': 'Birthdate must be in the past.',
            }),
            gender: Joi.string().valid('Male', 'Female').required(),
            phoneNumber: Joi.string().pattern(/^[0-9]{10}$/).required().messages({
                'string.pattern.base': 'Phone number must be exactly 10 digits.',
            }),
            email: Joi.string().email().required(),
            password: Joi.string().min(6).required(),
            role: Joi.string().valid('Student', 'Instructor').required()
        });

        const { error } = bodySchema.validate(req.body);
        if (error) {
            throw error;
        }

        // Prevent user set some fields that are not allowed
        userData.status = true;
        userData.refreshToken = null;
        userData.isVerified = false;
        userData.resetPasswordToken = null;
        newUser.loginProvider = ["None"]

        const newUser = (role == ROLES.STUDENT) ? new Student(userData) : new Instructor(userData)


        await newUser.save();

        await sendVerifyEmail(userData.email, userData.fullName);

        res.status(201).send();
    } catch (error) {
        next(error);
    }
}

export const verifyEmail = async (req, res, next) => {
    try {
        const token = req.query.token;
        if (!token) {
            throw new BadRequestError('No token provided');
        }

        const payload = jwtServices.verifyToken(token);
        if (payload.token_type != 'verify_token') {
            throw new BadRequestError('Invalid token type');
        }

        const email = payload.email;
        const user = await User.findOne(
            { email: email },
        );

        if (user.isVerified == true) {
            throw new BadRequestError("This email is adready verified");
        }
        else {
            user.isVerified = true;
            await user.save()
        }

        res.status(200).send();
    }
    catch (error) {
        next(error);
    }
}

export const requestResetPassword = async (req, res, next) => {
    try {
        const email = req.body.email
        if (!email || typeof email !== 'string') {
            throw new BadRequestError('Invalid request body.');
        }

        const user = await User.findOne({ email: email });
        if (!user) {
            throw new NotFoundError(`User with email ${email} doesn't exist`);
        }

        if (!user.isVerified || !user.status) {
            throw new ForbiddenError('This account is disabled')
        }

        let token;
        let tokenExists = true
        while (tokenExists) {
            token = crypto.randomBytes(32).toString('hex');
            //Check duplicate token
            tokenExists = await User.findOne({ 'resetPasswordToken.token': token });
        }
        const expiresAt = new Date(Date.now() + 30 * 60 * 1000); //30m

        user.resetPasswordToken = {
            token,
            expires: expiresAt
        };

        sendResetPasswordEmail(user.email, user.fullName, token)

        await user.save();

        res.status(200).send()
    }
    catch (error) {
        next(error)
    }
}

export const resetPassword = async (req, res, next) => {
    try {
        const { token, newPassword } = req.body
        const user = await User.findOne({ 'resetPasswordToken.token': token }).select('+resetPasswordToken +password');

        if (!user) {
            throw new BadRequestError("Invalid reset password token")
        }

        // Check if password is strong enough (at least 6 character, 1 Upcase letter, 1 Number and 1 Lowercase letter)
        const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{6,}$/;
        if (!passwordRegex.test(newPassword)) {
            throw new BadRequestError("Password is not strong is enough. Must have at least at least 6 characters and contains at least 1 Upcase letter, 1 Number and 1 Lowercase letter");
        }


        // Check expiration of token
        const currentTime = Date.now();
        const tokenExpires = user.resetPasswordToken.expires;
        if (currentTime > tokenExpires) {
            throw new BadRequestError("Reset password token expired")
        }

        //Hash new password and update for user
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(newPassword, saltRounds);
        user.password = hashedPassword;

        //Remove reset password token
        user.resetPasswordToken = null

        await user.save()

        res.status(200).send()
    }
    catch (error) {
        next(error)
    }
}

export const logout = (req, res, next) => {
    res.clearCookie("access_token");
    res.clearCookie("refresh_token");
    res.status(200).send()
}

const sendVerifyEmail = async (receiverEmail, name) => {
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        port: 587,
        secure: false,
        auth: {
            user: process.env.EMAIL_NAME,
            pass: process.env.EMAIL_PASS,
        }
    });

    const sendMailAsync = promisify(transporter.sendMail.bind(transporter));


    const verificationToken = jwtServices.generateVerificationToken({
        email: receiverEmail
    });

    const verificationLink = `${BASE_FE_URL}/verify-email?token=${verificationToken}`;

    const mailOptions = {
        from: 'Learn Sphere Website <LearnSphere@gmail.com>',
        to: receiverEmail,
        subject: 'Verify email',
        html: `
        <p>Hello ${name},</p>
        <p>Thank you for registering an account on our platform! To complete your registration, please confirm your email address by clicking the link below:</p>
        <p><a href="${verificationLink}">Confirm Your Email</a></p>
        <p>If you did not sign up for an account, you can safely ignore this email.</p>
        <p>We look forward to welcoming you to our platform!</p>
        <p>Best regards,<br>Hotel Zante Team</p>    
    `,
    };

    await sendMailAsync(mailOptions);

}

const sendResetPasswordEmail = async (receiverEmail, name, token) => {
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        port: 587,
        secure: false,
        auth: {
            user: process.env.EMAIL_NAME,
            pass: process.env.EMAIL_PASS,
        }
    });

    const sendMailAsync = promisify(transporter.sendMail.bind(transporter));

    const verificationLink = `${BASE_FE_URL}/forget-password?token=${token}`;

    const mailOptions = {
        from: 'Learn Sphere Website <LearnSphere@gmail.com>',
        to: receiverEmail,
        subject: 'Reset password',
        html: `
        <p>Hello ${name},</p>
        <p>We received a request to reset the password for your Learn Sphere account associated with this email. If you made this request, please click the link below:</p>
        <p><a href="${verificationLink}">Reset Password</a></p>
        <p>If you did not request a password reset, please ignore this email.</p>
        <p>Thank you for using our services!</p>
        <p>Best regards,<br>Learn Sphere Team</p>    
    `,
    };

    await sendMailAsync(mailOptions);

}

export const getCurrentUser = async (req, res, next) => {
    res.status(200).json({
        user_id: req.user.id,
        role: req.user.role
    });
}

export const getGoogleLoginUrl = async (req, res, next) => {
    const baseUrl = 'https://accounts.google.com/o/oauth2/v2/auth';

    const params = {
        client_id: process.env.GOOGLE_CLIENT_ID,
        redirect_uri: process.env.GOOGLE_REDIRECT_URI,
        response_type: 'code',
        scope: 'openid email profile',
        access_type: 'offline',
        prompt: 'consent'
    };

    // Build the full URL
    const loginUrl = `${baseUrl}?${querystring.stringify(params)}`;
    res.status(200).json({
        loginUrl
    })
}

export const handleGoogleCallback = async (req, res, next) => {
    try {
        const { code, role } = req.query;

        // Validate params
        const bodySchema = Joi.object({
            code: Joi.string().required(),
            role: Joi.string().valid('Student', 'Instructor').optional()
        }).unknown(true);

        const { error } = bodySchema.validate(req.query);
        if (error) {
            throw error;
        }


        if (!code) {
            return res.status(400).json({ error: 'Authorization code not provided!' });
        }

        // Exchange code for access token
        const tokenResponse = await axios.post('https://oauth2.googleapis.com/token', {
            code,
            client_id: process.env.GOOGLE_CLIENT_ID,
            client_secret: process.env.GOOGLE_CLIENT_SECRET,
            redirect_uri: process.env.GOOGLE_REDIRECT_URI,
            grant_type: 'authorization_code',
        });

        const { access_token, id_token } = tokenResponse.data;

        // Fetch user information using the access token
        const googleResponse = await axios.get('https://www.googleapis.com/oauth2/v2/userinfo', {
            headers: {
                Authorization: `Bearer ${access_token}`,
            },
        });

        const userInfo = googleResponse.data;

        // Check if user is already sign up with this email
        const existUser = await User.findOne({ email: userInfo.email });
        if (existUser) {
            await setTokenInCookie(existUser, res);
            res.status(200).send({
                user_id: existUser._id,
                role: existUser.role
            });
        }
        else {
            const newUser = {}
            newUser.email = userInfo.email
            newUser.fullName = userInfo.name
            newUser.status = true
            newUser.isVerified = true
            newUser.resetPasswordToken = null
            newUser.birthDate = null
            newUser.gender = null
            newUser.loginProvider = ["Google"]
            newUser.password = crypto.randomBytes(20).toString('hex') +"Salt1"
            const saveUser = (role == ROLES.INSTRUCTOR) ? new Instructor(newUser) : new Student(newUser)
            const savedUser = await saveUser.save()
            await setTokenInCookie(savedUser, res)
            res.status(200).send({
                user_id: savedUser._id,
                role: savedUser.role
            });
        }


    } catch (error) {
        next(error)
    }
}

