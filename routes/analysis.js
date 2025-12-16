// const express = require("express")
// const router = express.Router()
// const AIAnalyzer = require("../services/ai-analyzer")
// const { authenticateToken } = require("../middleware/auth")
// const fs = require("fs")
// const path = require("path")
// const mongoose = require("mongoose")

// // Import models (assuming they're defined in server.js or separate model files)
// const Review = mongoose.model("Review")
// const Project = mongoose.model("Project")
// const Issue = mongoose.model("Issue")

// const aiAnalyzer = new AIAnalyzer()

// router.post("/analyze-upload/:reviewId", authenticateToken, async (req, res) => {
//   try {
//     const { reviewId } = req.params
//     const userId = req.user.id

//     const review = await Review.findById(reviewId).populate({
//       path: "projectId",
//       match: { userId: userId },
//       select: "name userId",
//     })

//     if (!review || !review.projectId) {
//       return res.status(404).json({ success: false, message: "Review not found" })
//     }

//     const uploadPath = `uploads/${userId}`
//     if (!fs.existsSync(uploadPath)) {
//       return res.status(404).json({ success: false, message: "Upload directory not found" })
//     }

//     const files = fs.readdirSync(uploadPath)
//     const analysisResults = []
//     let totalIssues = 0
//     let securityIssues = 0
//     let performanceIssues = 0
//     let overallScore = 0

//     for (const file of files) {
//       const filePath = path.join(uploadPath, file)
//       const content = fs.readFileSync(filePath, "utf8")

//       const issues = await aiAnalyzer.analyzeFile(file, content)
//       const totalLines = content.split("\n").length

//       // Build a lightweight report compatible with previous shape
//       const report = {
//         filePath: file,
//         totalLines,
//         totalIssues: issues.length,
//         qualityScores: { overall: aiAnalyzer.scoreForIssues(issues, totalLines) },
//         // Optional summaries
//         categoryCounts: issues.reduce((acc, it) => {
//           acc[it.category] = (acc[it.category] || 0) + 1
//           return acc
//         }, {}),
//         severityCounts: issues.reduce((acc, it) => {
//           acc[it.severity] = (acc[it.severity] || 0) + 1
//           return acc
//         }, {}),
//       }

//       analysisResults.push(report)
//       totalIssues += issues.length
//       issues.forEach((issue) => {
//         if (issue.category === "security") securityIssues++
//         if (issue.category === "performance") performanceIssues++
//       })
//       overallScore += report.qualityScores.overall

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
//       }
//     }

//     const avgQualityScore = files.length > 0 ? overallScore / files.length : 0

//     await Review.findByIdAndUpdate(reviewId, {
//       status: "completed",
//       totalIssues,
//       securityIssues,
//       performanceIssues,
//       qualityScore: avgQualityScore,
//       updatedAt: new Date(),
//     })

//     res.json({
//       success: true,
//       analysis: {
//         totalFiles: files.length,
//         totalIssues,
//         securityIssues,
//         performanceIssues,
//         qualityScore: avgQualityScore,
//         results: analysisResults,
//       },
//     })
//   } catch (error) {
//     console.error("Analysis error:", error)
//     res.status(500).json({ success: false, message: "Analysis failed" })
//   }
// })

// router.get("/summary/:reviewId", authenticateToken, async (req, res) => {
//   try {
//     const { reviewId } = req.params
//     const userId = req.user.id

//     const review = await Review.findById(reviewId).populate({
//       path: "projectId",
//       match: { userId: userId },
//       select: "name userId",
//     })

//     if (!review || !review.projectId) {
//       return res.status(404).json({ success: false, message: "Review not found" })
//     }

//     const issueSummary = await Issue.aggregate([
//       { $match: { reviewId: mongoose.Types.ObjectId(reviewId) } },
//       { $group: { _id: { category: "$category", severity: "$severity" }, count: { $sum: 1 } } },
//       { $project: { category: "$_id.category", severity: "$_id.severity", count: 1, _id: 0 } },
//     ])

//     const topIssues = await Issue.find({ reviewId })
//       .sort({
//         severity: {
//           $cond: [
//             { $eq: ["$severity", "critical"] },
//             4,
//             { $cond: [{ $eq: ["$severity", "high"] }, 3, { $cond: [{ $eq: ["$severity", "medium"] }, 2, 1] }] },
//           ],
//         },
//         category: 1,
//       })
//       .limit(10)

//     res.json({
//       success: true,
//       summary: {
//         review: {
//           ...review.toObject(),
//           project_name: review.projectId.name,
//         },
//         issueSummary,
//         topIssues,
//       },
//     })
//   } catch (error) {
//     console.error("Summary error:", error)
//     res.status(500).json({ success: false, message: "Failed to fetch summary" })
//   }
// })

// module.exports = router
