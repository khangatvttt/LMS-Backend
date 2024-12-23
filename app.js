import connectDB from "./src/config/databaseConfig.js";
import dotenv from 'dotenv';
import cors from 'cors'
import cookieParser from 'cookie-parser';
import express from 'express'

import  { errorHandler }  from './src/middlewares/errorHandler.js'
import authRoutes from './src/routes/authRoute.js'
import jwtMiddleware from "./src/middlewares/jwtMiddleware.js";


dotenv.config();
const app = express();
const PORT = process.env.PORT || 5000;
const allowedOrigins = ['http://localhost:3000', 'http://localhost:3001'];

//Connect database
connectDB()

// Middleware
app.use(express.json()); // For parsing application/json
app.use(cookieParser()); // For parsing cookie

app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);

    if (allowedOrigins.indexOf(origin) === -1) {
      const msg = 'The CORS policy for this site does not allow access from the specified origin.';
      return callback(new Error(msg), false);
    }
    return callback(null, true);
  },
  credentials: true, // Allow cookies to be sent in requests
  methods: 'GET,HEAD,PUT,PATCH,POST,DELETE', // Allowed methods
  allowedHeaders: 'Content-Type, Authorization, X-Total-Count', // Headers that are allowed
  exposedHeaders: 'X-Total-Count',
}));


// Endpoint doesn't need jwt authentication
app.use('/api/auth', authRoutes)

app.use(jwtMiddleware)


//Error handler middleware
app.use(errorHandler);

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
  });