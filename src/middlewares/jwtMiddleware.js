import UnauthorizedError from "../errors/unauthorizedError.js";
import jwtServices from "../utils/jwtServices.js";

const jwtMiddleware = async (req, res, next) => {

    const bypassPaths = [
        { path: '/api/type-rooms', method: 'GET' },
        { path: '/api/ratings', method: 'GET' },

    ];

    const isBypassed = bypassPaths.some(
        (bypass) =>
            req.path.startsWith(bypass.path) && req.method === bypass.method
    );

    if (isBypassed) {
        return next();
    }

    try {
        // Retrieve access and refresh tokens from cookies
        const accessToken = req.cookies.access_token;

        if (!accessToken) {
            throw new UnauthorizedError('No access token provided.');
        }

        const decodedAccessToken = jwtServices.verifyToken(accessToken);

        if (decodedAccessToken.token_type !== 'access_token') {
            throw new UnauthorizedError('Invalid access token.');
        }
        req.user = {};
        req.user.id = decodedAccessToken.user_id;
        req.user.role = decodedAccessToken.role
        return next();

    } catch (err) {
        return next(err);
    }
};

export default jwtMiddleware;

