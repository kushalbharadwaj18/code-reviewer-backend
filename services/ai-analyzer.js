// // Uses dynamic import so it works in CommonJS
// const MAX_CONTENT_CHARS = 20000

// function truncateContent(content, limit = MAX_CONTENT_CHARS) {
//   if (!content || content.length <= limit) return content
//   const head = Math.floor(limit * 0.7)
//   const tail = limit - head
//   return `${content.slice(0, head)}\n...\n${content.slice(-tail)}`
// }

// function extractJson(text) {
//   try {
//     return JSON.parse(text)
//   } catch {
//     const fenced = text.match(/```json([\s\S]*?)```/i)
//     if (fenced) {
//       try {
//         return JSON.parse(fenced[1])
//       } catch {}
//     }
//     const startIdx = text.indexOf("{") !== -1 ? text.indexOf("{") : text.indexOf("[")
//     const endIdx = Math.max(text.lastIndexOf("}"), text.lastIndexOf("]"))
//     if (startIdx !== -1 && endIdx !== -1 && endIdx > startIdx) {
//       const candidate = text.slice(startIdx, endIdx + 1)
//       try {
//         return JSON.parse(candidate)
//       } catch {}
//     }
//   }
//   return null
// }

// class AIAnalyzer {
//   constructor() {
//     this.model = process.env.AI_MODEL || "google/gemini-2.0-flash"
//     this.maxIssuesPerFile = 25
//   }

//   async analyzeFile(filePath, content) {
//     const { generateText } = await import("ai")
//     const truncated = truncateContent(content)

//     const schemaHint = `
// Return ONLY JSON in the following shape:
// {
//   "filePath": "string",
//   "issues": [
//     {
//       "lineNumber": number,
//       "columnNumber": number | null,
//       "severity": "low" | "medium" | "high" | "critical",
//       "category": "security" | "performance" | "style" | "bug" | "maintainability",
//       "title": "string",
//       "description": "string",
//       "suggestion": "string",
//       "codeSnippet": "string",
//       "fixedCode": "string"
//     }
//   ]
// }
// Rules:
// - At most ${this.maxIssuesPerFile} issues per file
// - Prefer precise lineNumber and a short snippet around that line
// - Severity must be one of: low, medium, high, critical
// - Category must be one of: security, performance, style, bug, maintainability
// - If columnNumber is unknown, use null
// `

//     const prompt = `
// You are a professional code reviewer. Analyze the provided source file and report concrete issues with accurate line numbers, clear titles, descriptions, and actionable suggestions. Avoid generic advice.

// File: ${filePath}

// Content:
// """
// ${truncated}
// """

// ${schemaHint}
// `

//     const { text } = await generateText({
//       model: this.model,
//       prompt,
//     })

//     const json = extractJson(text) || { filePath, issues: [] }
//     const issues = Array.isArray(json.issues) ? json.issues : []

//     return issues.slice(0, this.maxIssuesPerFile).map((i) => ({
//       filePath,
//       lineNumber: Number.isFinite(i.lineNumber) ? i.lineNumber : 1,
//       columnNumber: Number.isFinite(i.columnNumber) ? i.columnNumber : 1,
//       severity: ["low", "medium", "high", "critical"].includes((i.severity || "").toLowerCase())
//         ? i.severity.toLowerCase()
//         : "low",
//       category: ["security", "performance", "style", "bug", "maintainability"].includes(
//         (i.category || "").toLowerCase(),
//       )
//         ? i.category.toLowerCase()
//         : "maintainability",
//       title: i.title || "Issue",
//       description: i.description || "No description provided",
//       suggestion: i.suggestion || "Add a concrete fix or improvement",
//       codeSnippet: i.codeSnippet || "",
//       fixedCode: i.fixedCode || "",
//     }))
//   }

//   scoreForIssues(issues, totalLines) {
//     let score = 100
//     for (const i of issues) {
//       switch (i.severity) {
//         case "critical":
//           score -= 15
//           break
//         case "high":
//           score -= 10
//           break
//         case "medium":
//           score -= 5
//           break
//         case "low":
//           score -= 2
//           break
//       }
//     }
//     const issueRate = (issues.length / Math.max(totalLines || 1, 1)) * 100
//     if (issueRate < 1) score += 5
//     return Math.max(0, Math.min(100, score))
//   }
// }

// module.exports = AIAnalyzer