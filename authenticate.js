
import jwt from "jsonwebtoken";

export function authenticate(req, res, next) {
  const authorization = req.headers.authorization;

  if (!authorization || !/^Bearer\s+\S+$/i.test(authorization)) {
    return res.status(401).json({
      error: "No token provided."
    });
  }

  const token = authorization.split(/\s+/)[1];

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({
      error: "Invalid or expired token."
    });
  }
}
