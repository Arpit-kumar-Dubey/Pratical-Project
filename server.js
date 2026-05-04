require("dotenv").config();

const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Joi = require("joi");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");

const app = express();
app.use(express.json());

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: {
    message: "Too many requests. Please try again later."
  }
});

app.use(limiter);

const users = [];
const tasks = [];
const refreshTokens = new Set();

const registerSchema = Joi.object({
  name: Joi.string().min(2).max(50).required(),
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
  adminCode: Joi.string().optional()
});

const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required()
});

const taskCreateSchema = Joi.object({
  title: Joi.string().min(2).max(100).required(),
  description: Joi.string().max(500).allow("").optional(),
  status: Joi.string().valid("pending", "in-progress", "completed").default("pending"),
  dueDate: Joi.date().iso().optional()
});

const taskUpdateSchema = Joi.object({
  title: Joi.string().min(2).max(100).optional(),
  description: Joi.string().max(500).allow("").optional(),
  status: Joi.string().valid("pending", "in-progress", "completed").optional(),
  dueDate: Joi.date().iso().optional()
}).min(1);

const refreshSchema = Joi.object({
  refreshToken: Joi.string().required()
});

function safeUser(user) {
  const { passwordHash, ...userWithoutPassword } = user;
  return userWithoutPassword;
}

function generateAccessToken(user) {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      role: user.role
    },
    process.env.JWT_ACCESS_SECRET,
    {
      expiresIn: process.env.ACCESS_TOKEN_EXPIRES_IN || "15m"
    }
  );
}

function generateRefreshToken(user) {
  return jwt.sign(
    {
      id: user.id,
      type: "refresh"
    },
    process.env.JWT_REFRESH_SECRET,
    {
      expiresIn: process.env.REFRESH_TOKEN_EXPIRES_IN || "7d"
    }
  );
}

function isDuplicateTaskTitle(userId, title, ignoreTaskId = null) {
  return tasks.some((task) => {
    return (
      task.userId === userId &&
      task.id !== ignoreTaskId &&
      task.title.toLowerCase() === title.toLowerCase()
    );
  });
}

function getPendingTasks(userId) {
  return tasks.filter((task) => {
    return task.userId === userId && task.status !== "completed";
  });
}

function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({
      message: "Authorization header missing"
    });
  }

  const parts = authHeader.split(" ");

  if (parts.length !== 2 || parts[0] !== "Bearer") {
    return res.status(401).json({
      message: "Invalid authorization format. Use Bearer token"
    });
  }

  const token = parts[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({
      message: "Invalid or expired token"
    });
  }
}

function requireAdmin(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({
      message: "Only admin can access this route"
    });
  }

  next();
}

function canAccessTask(user, task) {
  return user.role === "admin" || task.userId === user.id;
}

app.get("/", (req, res) => {
  res.json({
    message: "Secure Task Manager API is running"
  });
});

app.post("/api/auth/register", async (req, res) => {
  try {
    const { error, value } = registerSchema.validate(req.body);

    if (error) {
      return res.status(400).json({
        message: error.details[0].message
      });
    }

    const { name, email, password, adminCode } = value;

    const existingUser = users.find((user) => user.email === email);

    if (existingUser) {
      return res.status(409).json({
        message: "Email already registered"
      });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const role =
      adminCode === process.env.ADMIN_REGISTRATION_CODE ? "admin" : "user";

    const newUser = {
      id: crypto.randomUUID(),
      name,
      email,
      passwordHash,
      role,
      createdAt: new Date().toISOString()
    };

    users.push(newUser);

    res.status(201).json({
      message: "User registered successfully",
      user: safeUser(newUser)
    });
  } catch (error) {
    res.status(500).json({
      message: "Server error"
    });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { error, value } = loginSchema.validate(req.body);

    if (error) {
      return res.status(400).json({
        message: error.details[0].message
      });
    }

    const { email, password } = value;

    const user = users.find((user) => user.email === email);

    if (!user) {
      return res.status(401).json({
        message: "Invalid email or password"
      });
    }

    const isMatch = await bcrypt.compare(password, user.passwordHash);

    if (!isMatch) {
      return res.status(401).json({
        message: "Invalid email or password"
      });
    }

    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    refreshTokens.add(refreshToken);

    res.json({
      message: "Login successful",
      accessToken,
      refreshToken,
      user: safeUser(user)
    });
  } catch (error) {
    res.status(500).json({
      message: "Server error"
    });
  }
});

app.post("/api/auth/refresh", (req, res) => {
  const { error, value } = refreshSchema.validate(req.body);

  if (error) {
    return res.status(400).json({
      message: error.details[0].message
    });
  }

  const { refreshToken } = value;

  if (!refreshTokens.has(refreshToken)) {
    return res.status(403).json({
      message: "Invalid refresh token"
    });
  }

  try {
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);

    const user = users.find((user) => user.id === decoded.id);

    if (!user) {
      return res.status(404).json({
        message: "User not found"
      });
    }

    refreshTokens.delete(refreshToken);

    const newAccessToken = generateAccessToken(user);
    const newRefreshToken = generateRefreshToken(user);

    refreshTokens.add(newRefreshToken);

    res.json({
      accessToken: newAccessToken,
      refreshToken: newRefreshToken
    });
  } catch (error) {
    return res.status(403).json({
      message: "Expired or invalid refresh token"
    });
  }
});

app.post("/api/auth/logout", (req, res) => {
  const { refreshToken } = req.body;

  if (refreshToken) {
    refreshTokens.delete(refreshToken);
  }

  res.json({
    message: "Logged out successfully"
  });
});

app.get("/api/me", authenticateToken, (req, res) => {
  const user = users.find((user) => user.id === req.user.id);

  res.json({
    user: safeUser(user)
  });
});

app.post("/api/tasks", authenticateToken, (req, res) => {
  const { error, value } = taskCreateSchema.validate(req.body);

  if (error) {
    return res.status(400).json({
      message: error.details[0].message
    });
  }

  const { title, description, status, dueDate } = value;

  if (isDuplicateTaskTitle(req.user.id, title)) {
    return res.status(409).json({
      message: "Task with same title already exists"
    });
  }

  const newTask = {
    id: crypto.randomUUID(),
    userId: req.user.id,
    title,
    description: description || "",
    status: status || "pending",
    dueDate: dueDate ? new Date(dueDate).toISOString() : null
  };

  tasks.push(newTask);

  res.status(201).json({
    message: "Task created successfully",
    task: newTask
  });
});

app.get("/api/tasks", authenticateToken, (req, res) => {
  if (req.user.role === "admin") {
    return res.json({
      tasks
    });
  }

  const userTasks = tasks.filter((task) => task.userId === req.user.id);

  res.json({
    tasks: userTasks
  });
});

app.get("/api/tasks/pending", authenticateToken, (req, res) => {
  if (req.user.role === "admin") {
    const pendingTasks = tasks.filter((task) => task.status !== "completed");

    return res.json({
      pendingTasks
    });
  }

  const pendingTasks = getPendingTasks(req.user.id);

  res.json({
    pendingTasks
  });
});

app.put("/api/tasks/:id", authenticateToken, (req, res) => {
  const { error, value } = taskUpdateSchema.validate(req.body);

  if (error) {
    return res.status(400).json({
      message: error.details[0].message
    });
  }

  const task = tasks.find((task) => task.id === req.params.id);

  if (!task) {
    return res.status(404).json({
      message: "Task not found"
    });
  }

  if (!canAccessTask(req.user, task)) {
    return res.status(403).json({
      message: "You are not allowed to update this task"
    });
  }

  if (value.title && isDuplicateTaskTitle(task.userId, value.title, task.id)) {
    return res.status(409).json({
      message: "Task with same title already exists"
    });
  }

  if (value.title !== undefined) task.title = value.title;
  if (value.description !== undefined) task.description = value.description;
  if (value.status !== undefined) task.status = value.status;
  if (value.dueDate !== undefined) {
    task.dueDate = new Date(value.dueDate).toISOString();
  }

  res.json({
    message: "Task updated successfully",
    task
  });
});

app.patch("/api/tasks/:id/complete", authenticateToken, (req, res) => {
  const task = tasks.find((task) => task.id === req.params.id);

  if (!task) {
    return res.status(404).json({
      message: "Task not found"
    });
  }

  if (!canAccessTask(req.user, task)) {
    return res.status(403).json({
      message: "You are not allowed to complete this task"
    });
  }

  task.status = "completed";

  res.json({
    message: "Task marked as completed",
    task
  });
});

app.delete("/api/tasks/:id", authenticateToken, (req, res) => {
  const taskIndex = tasks.findIndex((task) => task.id === req.params.id);

  if (taskIndex === -1) {
    return res.status(404).json({
      message: "Task not found"
    });
  }

  const task = tasks[taskIndex];

  if (!canAccessTask(req.user, task)) {
    return res.status(403).json({
      message: "You are not allowed to delete this task"
    });
  }

  tasks.splice(taskIndex, 1);

  res.json({
    message: "Task deleted successfully"
  });
});

app.get("/api/admin/users", authenticateToken, requireAdmin, (req, res) => {
  res.json({
    users: users.map(safeUser)
  });
});

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});