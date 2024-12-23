import dotenv from 'dotenv';

dotenv.config();

export const errorHandler = (err, req, res, next) => {
    // Default status code to 500 (internal server error)
    let statusCode = err.statusCode || 500;
    let message = err.message;


    // Handle Mongoose validation errors
    if (err.name === 'ValidationError') {
        statusCode = 400;
        //message = Object.values(err.errors).map((error) => error.message).join(', ');
    }

    // Handle invalid ObjectId (CastError)
    if (err.name === 'CastError' && err.kind === 'ObjectId') {
        statusCode = 400;
        message = `Invalid ${err.path}: ${err.value}`;
    }

    // Handle duplicate key errors (e.g., unique constraint violations)
    if (err.code === 11000) {
        statusCode = 400;
        const field = Object.keys(err.keyValue)[0];
        message = `Duplicate value for field '${field}'`;
    }

    // Excess number of file allowed
    if (err.code === 'LIMIT_UNEXPECTED_FILE'){
        statusCode = 400;
        message = `Maximum images can upload is ${process.env.MAX_IMAGES}`
    }

    // Excess limit of file allowed
    if (err.code === 'LIMIT_FILE_SIZE'){
        statusCode = 400;
        message = `File too large, excess limit file size allowed (${process.env.MAX_FILE_SIZE/1024/1024}MB)`
    }


    if (err.name == 'TypeError') {
        statusCode = 400;
        //message = 'Invalid request body.';
        message = err.message
    }

    if (err.name === 'TokenExpiredError') {
        statusCode = 400;
        message = 'Token expired'
    }

    if (err.message && err.message.includes("sendMail")) {
        message= 'Failed to send email.'
    }

    // Handle other types of errors (if any)
    res.status(statusCode).json({
        error: {
            status: statusCode,
            message: message,
            timestamp: new Date().toISOString(),
            path: req.path,
        }
    });
};
