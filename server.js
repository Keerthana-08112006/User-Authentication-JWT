require("dotenv").config();

const express = require("express");
const authRoutes = require("./auth");
const authenticateToken = require("./middleware");
const db = require("./database/db");

const app = express();
const PORT = process.env.PORT || 5000;

app.use(express.json());

app.get("/", (req, res) => {
  res.json({
    message: "User Authentication & JWT API is running!"
  });
});

app.use("/api/auth", authRoutes);

// Protected route: requires a valid JWT
app.get("/api/profile", authenticateToken, (req, res) => {
  db.get(
    "SELECT id, name, email, created_at FROM users WHERE id = ?",
    [req.user.id],
    (err, user) => {
      if (err) {
        return res.status(500).json({ error: "Unable to load profile." });
      }

      if (!user) {
        return res.status(404).json({ error: "User not found." });
      }

      res.json({
        message: "Protected profile accessed successfully.",
        user
      });
    }
  );
});

app.get("/api/health", (req, res) => {
  res.json({ status: "ok" });
});

app.listen(PORT, () => {
  console.log(`Authentication API running at http://localhost:${PORT}`);
});
