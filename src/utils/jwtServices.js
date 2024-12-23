import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config()

const secretKey = process.env.JWT_SECRET_KEY
const expiredAccessTime = process.env.ACCESS_TOKEN_EXPIRATION
const expiredRefreshTime = process.env.REFRESH_TOKEN_EXPIRATION


const generateAccessToken = (payload) => {
  const newPayload = {
    ...payload,
    token_type: 'access_token',
  };
  const options = {
    expiresIn: expiredAccessTime,
  };

  const token = jwt.sign(newPayload, secretKey, options);
  return token;
};

const generateRefreshToken = (oldRefreshToken, payload) => {
  const newPayload = {
    ...payload,
    token_type: 'refresh_token',
  };
  let options = {
    expiresIn: expiredRefreshTime,
  };

  const decodedOldToken = jwt.decode(oldRefreshToken);

  // Rotate refresh token with the same expired time
  if (decodedOldToken && decodedOldToken.exp) {
    // Calculate the remaining time for the old token
    const remainingTime = decodedOldToken.exp - Math.floor(Date.now() / 1000);
    options.expiresIn = `${remainingTime}s`; 
  }

  const token = jwt.sign(newPayload, secretKey, options);
  return token;
};

const generateVerificationToken = (payload) => {
  const newPayload = {
    ...payload,
    token_type: 'verify_token',
  };
  let options = {
    expiresIn: expiredAccessTime,
  };

  const token = jwt.sign(newPayload, secretKey, options);
  return token;
};

const verifyToken = (token) => {
  return jwt.verify(token, secretKey);
};




export default {
  generateAccessToken,
  generateRefreshToken,
  generateVerificationToken,
  verifyToken
};