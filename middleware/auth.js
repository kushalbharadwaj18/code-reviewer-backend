const jwt = require("jsonwebtoken")
const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key-change-in-production"

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"]
  const token = authHeader && authHeader.split(" ")[1]

  if (!token) {
    return res.status(401).json({ success: false, message: "Access token required" })
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ success: false, message: "Invalid token" })
    }
    req.user = user
    next()
  })
}

const requireRole = (role) => {
  return (req, res, next) => {
    if (req.user.role !== role && req.user.role !== "admin") {
      return res.status(403).json({ success: false, message: "Insufficient permissions" })
    }
    next()
  }
}

module.exports = { authenticateToken, requireRole }
