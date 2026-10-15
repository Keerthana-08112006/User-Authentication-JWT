const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const db = require("./database/db");

const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET;

function createToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email },
    JWT_SECRET,
    { expiresIn: "1h" }
  );
}

// Register a new user
router.post("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (
      typeof name !== "string" ||
      !name.trim() ||
      typeof email !== "string" ||
      !email.trim() ||
      typeof password !== "string" ||
      password.length < 8
    ) {
      return res.status(400).json({
        error: "Name and email are required. Password must be at least 8 characters."
      });
    }

    const normalizedEmail = email.trim().toLowerCase();
    const hashedPassword = await bcrypt.hash(password, 12);

    db.run(
      "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
      [name.trim(), normalizedEmail, hashedPassword],
      function (err) {
        if (err) {
          if (err.code === "SQLITE_CONSTRAINT") {
            return res.status(409).json({ error: "Email already registered." });
          }
          return res.status(500).json({ error: "Registration failed." });
        }

        res.status(201).json({
          message: "Registration successful.",
          user: { id: this.lastID, name: name.trim(), email: normalizedEmail }
        });
      }
    );
  } catch {
    res.status(500).json({ error: "Registration failed." });
  }
});

// Log in an existing user
router.post("/login", (req, res) => {
  const { email, password } = req.body;

  if (
    typeof email !== "string" ||
    typeof password !== "string" ||
    !email.trim() ||
    !password
  ) {
    return res.status(400).json({ error: "Email and password are required." });
  }

  const normalizedEmail = email.trim().toLowerCase();

  db.get(
    "SELECT id, name, email, password FROM users WHERE email = ?",
    [normalizedEmail],
    async (err, user) => {
      if (err) {
        return res.status(500).json({ error: "Login failed." });
      }

      if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ error: "Invalid email or password." });
      }

      const token = createToken(user);

      res.json({
        message: "Login successful.",
        token,
        user: { id: user.id, name: user.name, email: user.email }
      });
    }
  );
});

module.exports = router;
