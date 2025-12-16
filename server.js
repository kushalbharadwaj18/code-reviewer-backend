const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const { v4: uuidv4 } = require("uuid");
const mongoose = require("mongoose");
const dotenv = require("dotenv").config();
const axios = require("axios");
const { getSystemErrorMap } = require("util");
const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET =
  process.env.JWT_SECRET || "your-secret-key-change-in-production";
const MONGODB_URI = process.env.MONGODB_URI;

// app.use(
//   cors({
//     origin: "http://localhost:5173", // your frontend URL
//     credentials: true, // allow cookies/auth headers if needed
//   })
// );

app.use(cors());
app.use(express.json());
// app.use("/uploads", express.static("uploads"))

// if (!fs.existsSync("uploads")) {
//   fs.mkdirSync("uploads")
// }
const upload = multer({
  dest: "uploads/", // files will be temporarily stored here
  limits: { fileSize: 10 * 1024 * 1024 }, // limit: 10MB
});

mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const db = mongoose.connection;
db.on("error", console.error.bind(console, "MongoDB connection error:"));
db.once("open", () => {
  console.log("Connected to MongoDB");
});

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

const projectSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  name: { type: String, required: true },
  description: String,
  type: { type: String, required: true }, // 'upload' or 'repository'
  repositoryUrl: String,
  branch: { type: String, default: "main" },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

const reviewSchema = new mongoose.Schema({
  // status: { type: String, default: "pending" }, // 'pending', 'completed', 'failed'
  totalFiles: { type: Number, default: 0 },
  // totalIssues: { type: Number, default: 0 },
  // securityIssues: { type: Number, default: 0 },
  userId: {type: String},
  projectName: {type: String},
  description: {type: String},
  reviewText: { type: String, required: true },
  // performanceIssues: { type: Number, default: 0 },
  qualityScore: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

// const issueSchema = new mongoose.Schema({
//   reviewId: { type: mongoose.Schema.Types.ObjectId, ref: "Review", required: true },
//   filePath: { type: String, required: true },
//   lineNumber: Number,
//   columnNumber: Number,
//   severity: { type: String, required: true }, // 'low', 'medium', 'high', 'critical'
//   category: { type: String, required: true }, // 'security', 'performance', 'style', 'bug', 'maintainability'
//   title: { type: String, required: true },
//   description: { type: String, required: true },
//   suggestion: String,
//   codeSnippet: String,
//   fixedCode: String,
//   status: { type: String, default: "open" }, // 'open', 'fixed', 'ignored'
//   createdAt: { type: Date, default: Date.now },
// })

// const teamMemberSchema = new mongoose.Schema({
//   userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
//   teamOwnerId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
//   role: { type: String, default: "member" }, // 'owner', 'admin', 'member'
//   createdAt: { type: Date, default: Date.now },
// })

const User = mongoose.model("User", userSchema);
const Project = mongoose.model("Project", projectSchema);
const Review = mongoose.model("Review", reviewSchema);
// const Issue = mongoose.model("Issue", issueSchema)
// const TeamMember = mongoose.model("TeamMember", teamMemberSchema)

// const storage = multer.diskStorage({
//   destination: (req, file, cb) => {
//     const uploadPath = `uploads/${req.user.id}`
//     if (!fs.existsSync(uploadPath)) {
//       fs.mkdirSync(uploadPath, { recursive: true })
//     }
//     cb(null, uploadPath)
//   },
//   filename: (req, file, cb) => {
//     cb(null, `${uuidv4()}-${file.originalname}`)
//   },
// })

// const upload = multer({
//   storage,
//   limits: { fileSize: 50 * 1024 * 1024 }, // 50MB limit
//   fileFilter: (req, file, cb) => {
//     const allowedTypes = [
//       ".js",
//       ".jsx",
//       ".ts",
//       ".tsx",
//       ".py",
//       ".java",
//       ".cpp",
//       ".c",
//       ".cs",
//       ".php",
//       ".rb",
//       ".go",
//       ".rs",
//       ".swift",
//       ".kt",
//       ".scala",
//       ".html",
//       ".css",
//       ".scss",
//       ".less",
//       ".json",
//       ".xml",
//       ".yaml",
//       ".yml",
//       ".md",
//       ".txt",
//       ".sql",
//     ]

//     const ext = path.extname(file.originalname).toLowerCase()
//     if (allowedTypes.includes(ext) || file.mimetype === "application/zip") {
//       cb(null, true)
//     } else {
//       cb(new Error("File type not supported"), false)
//     }
//   },
// })

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res
      .status(401)
      .json({ success: false, message: "Access token required" });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ success: false, message: "Invalid token" });
    }
    req.user = user;
    next();
  });
};

app.post("/api/auth/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res
        .status(400)
        .json({ success: false, message: "All fields are required" });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: "Password must be at least 6 characters",
      });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res
        .status(400)
        .json({ success: false, message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
      name,
      email,
      password: hashedPassword,
    });

    await user.save();

    const token = jwt.sign({ id: user._id, email, name }, JWT_SECRET, {
      expiresIn: "7d",
    });

    res.json({
      success: true,
      token,
      user: { id: user._id, name, email },
    });
  } catch (error) {
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res
        .status(400)
        .json({ success: false, message: "Email and password are required" });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res
        .status(400)
        .json({ success: false, message: "Invalid credentials" });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res
        .status(400)
        .json({ success: false, message: "Invalid credentials" });
    }

    const token = jwt.sign(
      { id: user._id, email: user.email, name: user.name },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      success: true,
      token,
      user: { id: user._id, name: user.name, email: user.email },
    });
  } catch (error) {
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.get("/api/auth/verify", authenticateToken, (req, res) => {
  res.json({
    success: true,
    user: { id: req.user.id, name: req.user.name, email: req.user.email },
  });
});

// app.get("/api/dashboard/stats", authenticateToken, async (req, res) => {
//   try {
//     const userId = req.user.id

//     const [totalProjects, totalReviews, totalIssues, avgQualityScore] = await Promise.all([
//       Project.countDocuments({ userId }),
//       Review.countDocuments({ projectId: { $in: await Project.find({ userId }).distinct("_id") } }),
//       Issue.countDocuments({
//         reviewId: {
//           $in: await Review.find({ projectId: { $in: await Project.find({ userId }).distinct("_id") } }).distinct(
//             "_id",
//           ),
//         },
//       }),
//       Review.aggregate([
//         { $match: { projectId: { $in: await Project.find({ userId }).distinct("_id") }, status: "completed" } },
//         { $group: { _id: null, avgScore: { $avg: "$qualityScore" } } },
//       ]),
//     ])

//     const stats = {
//       totalProjects,
//       totalReviews,
//       totalIssues,
//       avgQualityScore: avgQualityScore[0]?.avgScore || 0,
//     }

//     res.json({ success: true, stats })
//   } catch (error) {
//     res.status(500).json({ success: false, message: "Failed to fetch stats" })
//   }
// })

// app.get("/api/dashboard/recent-reviews", authenticateToken, async (req, res) => {
//   try {
//     const userId = req.user.id

//     const reviews = await Review.find({ projectId: { $in: await Project.find({ userId }).distinct("_id") } })
//       .populate("projectId", "name type")
//       .sort({ createdAt: -1 })
//       .limit(5)

//     const formattedReviews = reviews.map((review) => ({
//       ...review.toObject(),
//       project_name: review.projectId.name,
//       project_type: review.projectId.type,
//     }))

//     res.json({ success: true, reviews: formattedReviews })
//   } catch (error) {
//     res.status(500).json({ success: false, message: "Failed to fetch recent reviews" })
//   }
// })

// app.post("/api/projects", authenticateToken, async (req, res) => {
//   try {
//     const { name, description, type, repository_url, branch } = req.body
//     const userId = req.user.id

//     if (!name || !type) {
//       return res.status(400).json({ success: false, message: "Name and type are required" })
//     }

//     const project = new Project({
//       userId,
//       name,
//       description,
//       type,
//       repositoryUrl: repository_url,
//       branch: branch || "main",
//     })

//     await project.save()

//     res.json({
//       success: true,
//       project: {
//         id: project._id,
//         name,
//         description,
//         type,
//         repository_url,
//         branch: branch || "main",
//       },
//     })
//   } catch (error) {
//     res.status(500).json({ success: false, message: "Failed to create project" })
//   }
// })

// app.get("/api/projects", authenticateToken, async (req, res) => {
//   try {
//     const userId = req.user.id

//     const projects = await Project.find({ userId }).sort({ createdAt: -1 })
//     res.json({ success: true, projects })
//   } catch (error) {
//     res.status(500).json({ success: false, message: "Failed to fetch projects" })
//   }
// })

// const AIAnalyzer = require("./services/ai-analyzer")
// const aiAnalyzer = new AIAnalyzer()

// app.post("/api/upload", authenticateToken, upload.array("files", 50), async (req, res) => {
//   try {
//     if (!req.files || req.files.length === 0) {
//       return res.status(400).json({ success: false, message: "No files uploaded" })
//     }

//     const { projectName, description } = req.body
//     const userId = req.user.id

//     const project = new Project({
//       userId,
//       name: projectName || "Uploaded Files",
//       description: description || "",
//       type: "upload",
//     })

//     await project.save()
//     // console.log(req.files);
//     const review = new Review({
//       projectId: project._id,
//       totalFiles: req.files.length,
//       reviewText: "Code review in progress...",
//     })

//     await review.save()

//     // setTimeout(() => {
//     //   analyzeUploadedFiles(review._id, req.files)
//     // }, 1000)

//     res.json({
//       success: true,
//       project: { id: project._id, name: projectName },
//       review: { id: review._id, status: "pending" },
//       files: req.files.map((file) => ({
//         filename: file.filename,
//         originalname: file.originalname,
//         size: file.size,
//       })),
//     })
//   } catch (error) {
//     res.status(500).json({ success: false, message: "Upload failed" })
//   }
// })

app.get("/api/reviews", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id

    const reviews = await Review.find({ userId })

    // const formattedReviews = reviews.map((review) => ({
    //   ...review.toObject(),
    // }))

    res.json({ success: true, reviews: reviews })
  } catch (error) {
    res.status(500).json({ success: false, message: "Failed to fetch reviews" })
  }
})

app.get("/api/reviews/:id", authenticateToken, async (req, res) => {
  try {
    const reviewId = req.params.id;
    const userId = req.user.id;
    // ✅ Correct usage: pass the ID directly to findById
    const review = await Review.findById({ _id: reviewId });
    // console.log(review);

    if (!review) {
      return res.status(404).json({ success: false, message: "Review not found" });
    }

    // ✅ Return actual review data
    res.json({
      success: true,
      reviewText: review.reviewText,
      qualityScore: review.qualityScore,
      totalFiles: review.totalFiles,
      createdAt: review.createdAt,
      id: review._id
    });
  } catch (error) {
    console.error("Fetch review error:", error);
    res.status(500).json({ success: false, message: "Failed to fetch review" });
  }
});


// async function analyzeUploadedFiles(reviewId, files) {
//   try {
//     let totalIssues = 0
//     let securityIssues = 0
//     let performanceIssues = 0
//     let totalLinesAll = 0

//     for (const file of files) {
//       const fullPath = file.path || path.join("uploads", String(file.userId || ""), file.filename)
//       const content = fs.readFileSync(fullPath, "utf8")
//       const issues = await aiAnalyzer.analyzeFile(file.originalname || file.filename, content)
//       const totalLines = content.split("\n").length
//       totalLinesAll += totalLines

//       for (const issue of issues) {
//         const newIssue = new Issue({
//           reviewId,
//           filePath: issue.filePath,
//           lineNumber: issue.lineNumber,
//           columnNumber: issue.columnNumber,
//           severity: issue.severity,
//           category: issue.category,
//           title: issue.title,
//           description: issue.description,
//           suggestion: issue.suggestion,
//           codeSnippet: issue.codeSnippet,
//           fixedCode: issue.fixedCode,
//         })
//         await newIssue.save()

//         totalIssues++
//         if (issue.category === "security") securityIssues++
//         if (issue.category === "performance") performanceIssues++
//       }
//     }

//     const qualityScore = aiAnalyzer.scoreForIssues({ length: totalIssues }, totalLinesAll)

//     await Review.findByIdAndUpdate(reviewId, {
//       status: "completed",
//       totalIssues,
//       securityIssues,
//       performanceIssues,
//       qualityScore,
//       updatedAt: new Date(),
//     })
//   } catch (err) {
//     console.error("[v0] analyzeUploadedFiles error:", err.message)
//     await Review.findByIdAndUpdate(reviewId, {
//       status: "failed",
//       updatedAt: new Date(),
//     })
//   }
// }

// Allow multiple file uploads

async function reviewCode(code) {
  // const response = await axios.post("http://localhost:3000/ai/get-review", { code });
  // return response.data; // already JSON, no need to stringify here
  const response = await fetch("http://127.0.0.1:3000/review", { 
    method: 'POST',
    body: JSON.stringify({ code }),
    headers: { 'Content-Type': 'application/json' }
  });
  const data = await response.json();
  return data;
}

app.post("/api/upload", authenticateToken, upload.array("files", 10), async (req, res) => {
  try {
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({
        success: false,
        message: "No files uploaded",
      });
    }

    const textFileTypes = [
      ".txt",
      ".js",
      ".json",
      ".py",
      ".java",
      ".cpp",
      ".html",
      ".css",
      ".md",
    ];

    let userId = req.user.id;

    let review = "";

    // ✅ process files sequentially to await each review
    const extractedFiles = [];
    let reviewedText = null;
    for (const file of req.files) {
      const filePath = file.path;
      const fileName = file.originalname;
      const fileExt = path.extname(fileName).toLowerCase();
      let fileContent = "";

      try {
        if (textFileTypes.includes(fileExt)) {
          fileContent = fs.readFileSync(filePath, "utf8");
        } else {
          fileContent = `Unsupported file type: ${fileExt}`;
        }
      } catch (err) {
        fileContent = "Error reading file";
      }

      // cleanup uploaded temp file
      fs.unlinkSync(filePath);

      // ✅ await the AI review
      reviewedText = await reviewCode(fileContent);
      review += `File: ${fileName}\nReview:\n${reviewedText.review}\n\n`;

      extractedFiles.push({
        name: fileName,
        size: file.size,
        type: fileExt,
        content: fileContent,
      });
    }
    // ✅ Save to MongoDB and return review ID
    const qualityScore = reviewedText?.quality_score;
    const validQualityScore = typeof qualityScore === 'number' && !isNaN(qualityScore) ? qualityScore : 0;
    
    const newReview = new Review({
      userId: userId,
      projectName: req.body.projectName || "Uploaded Files",
      description: req.body.description || "",
      totalFiles: req.files.length,
      reviewText: review,
      qualityScore: validQualityScore,
    });

    await newReview.save();

    res.json({
      success: true,
      message: "Files processed successfully",
      review: { id: newReview._id }, // ✅ returning review.id
      totalFiles: extractedFiles.length,
      files: extractedFiles,
    });
  } catch (error) {
    console.error("Upload error:", error);
    res.status(500).json({
      success: false,
      message: "Error processing files",
    });
  }
});



const CLIENT_ID = process.env.GITHUB_CLIENT_ID;
const CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET;
const CLIENT_URL = process.env.CLIENT_URL;

// --- Step 1: Redirect user to GitHub OAuth ---
app.get("/api/auth/github/login", (req, res) => {
  const redirect_uri = "http://localhost:5000/api/auth/github/callback";
  const githubAuthURL = `https://github.com/login/oauth/authorize?client_id=${CLIENT_ID}&redirect_uri=${redirect_uri}&scope=repo,user`;
  res.redirect(githubAuthURL);
});

// --- Step 2: GitHub redirects here with code ---
app.get("/api/auth/github/callback", async (req, res) => {
  const code = req.query.code;

  if (!code) return res.status(400).send("Missing code");

  try {
    const tokenResponse = await fetch("https://github.com/login/oauth/access_token", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        code,
      }),
    });

    const tokenData = await tokenResponse.json();
    const access_token = tokenData.access_token;

    if (!access_token) {
      return res.status(400).json({ success: false, message: "Failed to get token" });
    }

    const userResponse = await fetch("https://api.github.com/user", {
      headers: { Authorization: `Bearer ${access_token}` },
    });
    const user = await userResponse.json();

    // Redirect to frontend with token + user info
    const redirectURL = `${CLIENT_URL}/repositories?token=${access_token}&user=${user.login}`;
    res.redirect(redirectURL);
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "OAuth failed" });
  }
});

// --- Step 3: Fetch user's repositories ---
app.get("/api/auth/github/repos", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ success: false, message: "Missing token" });

  try {
    const response = await fetch("https://api.github.com/user/repos", {
      headers: { Authorization: `Bearer ${token}` },
    });
    const repos = await response.json();
    res.json({ success: true, repos });
  } catch (err) {
    res.status(500).json({ success: false, message: "Failed to fetch repos" });
  }
});

// app.get("/", (req, res) => {
//   res.send("GitHub OAuth Backend Running ✅");
// });

app.post("/api/review/repo", authenticateToken, async (req, res) => {
  try {
    const { repo_url, branch, token } = req.body;
    const userId = req.user.id;

    if (!repo_url) {
      return res.status(400).json({ success: false, message: "Repository URL is required" });
    }

    // 🧹 Clean the repo URL (remove trailing .git)
    const cleanUrl = repo_url.replace(/\.git$/, "");

    // 🧩 Extract owner and repo name
    const match = cleanUrl.match(/github\.com\/([^/]+)\/([^/]+)/);
    if (!match) {
      return res.status(400).json({ success: false, message: "Invalid GitHub repository URL" });
    }

    const owner = match[1];
    const repo = match[2];
    const branchName = branch || "main";

    console.log(`🔍 Fetching files from ${owner}/${repo} (${branchName})`);

    // 🗂️ Fetch repo tree (list of files)
    const treeResponse = await axios.get(
      `https://api.github.com/repos/${owner}/${repo}/git/trees/${branchName}?recursive=1`,
      { headers: { Authorization: `Bearer ${token}` } }
    );

    if (!treeResponse.data.tree) {
      return res.status(404).json({ success: false, message: "No files found in repo" });
    }

    // 🎯 Filter only relevant code files
    const files = treeResponse.data.tree.filter(
      (item) =>
        item.type === "blob" &&
        /\.(js|ts|py|java|cpp|c|cs|html|css|json|md|txt)$/i.test(item.path)
    );

    console.log(`📁 Found ${files.length} files for analysis`);

    let reviewText = "";

    // ⚙️ Loop through limited files for AI review
    let qualityScore = 0;
    for (const file of files.slice(0, 10)) {
      try {
        // Each blob has its own API URL for content
        const fileContentRes = await axios.get(file.url, {
          headers: { Authorization: `Bearer ${token}` },
        });

        const encodedContent = fileContentRes.data.content;
        const decodedContent = Buffer.from(encodedContent, "base64").toString("utf8");

        // 🧠 Send content to your AI review logic (replace with your function)
        const aiReview = await reviewCode(decodedContent);

        reviewText += `\n\n---\n📄 File: ${file.path}\n${aiReview.review}`;
        qualityScore += aiReview.quality_score;
      } catch (err) {
        console.error(`⚠️ Error reading file ${file.path}:`, err.message);
      }
    }

    // 📊 Random quality score (50–100)

    // 💾 Save review to database
    const newReview = new Review({
      userId,
      projectName: repo,
      description: `Automated review for ${repo}`,
      totalFiles: files.length,
      reviewText,
      qualityScore: qualityScore / files.length,
    });

    await newReview.save();

    // ✅ Send response
    res.json({
      success: true,
      message: "Repository reviewed successfully",
      review: {
        id: newReview._id,
        totalFiles: files.length,
        qualityScore: newReview.qualityScore,
      },
    });
  } catch (error) {
    console.error("❌ Repo review error:", error.response?.data || error.message);
    res.status(500).json({
      success: false,
      message: error.response?.data?.message || "Failed to review repository",
    });
  }
});

app.put("/api/user/profile", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const { name, email } = req.body;

    const user = await User.findById(userId);
    if (!user)
      return res.status(404).json({ success: false, message: "User not found" });

    user.name = name || user.name;
    user.email = email || user.email;
    await user.save();

    res.json({ success: true, message: "Profile updated successfully" });
  } catch (error) {
    console.error("Profile update error:", error);
    res.status(500).json({ success: false, message: "Failed to update profile" });
  }
});

app.put("/api/user/password", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const { currentPassword, newPassword } = req.body;

    const user = await User.findById(userId);
    if (!user)
      return res.status(404).json({ success: false, message: "User not found" });

    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch)
      return res.status(400).json({ success: false, message: "Current password is incorrect" });

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();

    res.json({ success: true, message: "Password updated successfully" });
  } catch (error) {
    console.error("Password change error:", error);
    res.status(500).json({ success: false, message: "Failed to change password" });
  }
});

app.delete("/api/user/delete", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;

    await User.findByIdAndDelete(userId);
    await Review.deleteMany({ userId });

    res.json({ success: true, message: "Account and associated reviews deleted successfully" });
  } catch (error) {
    console.error("Account deletion error:", error);
    res.status(500).json({ success: false, message: "Failed to delete account" });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
