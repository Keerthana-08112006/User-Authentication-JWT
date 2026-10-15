const jwt = require("jsonwebtoken");

function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({
      error: "Access denied. Please provide a Bearer token."
    });
  }

  const token = authHeader.slice(7);
  const secret = process.env.JWT_SECRET;

  if (!secret) {
    return res.status(500).json({
      error: "Authentication configuration is missing."
    });
  }

  try {
    const decoded = jwt.verify(token, secret);

    if (
      !decoded ||
      !Number.isInteger(decoded.id) ||
      typeof decoded.email !== "string"
    ) {
      return res.status(401).json({ error: "Invalid token claims." });
    }

    req.user = {
      id: decoded.id,
      email: decoded.email
    };

    next();
  } catch {
    return res.status(401).json({
      error: "Invalid or expired token."
    });
  }
}

module.exports = authenticateToken;