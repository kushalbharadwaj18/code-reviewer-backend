// const fs = require("fs")
// const path = require("path")

// class EnhancedCodeAnalyzer {
//   constructor() {
//     this.rules = {
//       security: [
//         {
//           pattern: /eval\s*\(/g,
//           severity: "critical",
//           title: "Dangerous eval() usage",
//           description: "Using eval() can lead to code injection vulnerabilities",
//           suggestion: "Avoid using eval(). Use safer alternatives like JSON.parse() for JSON data",
//           cwe: "CWE-95",
//         },
//         {
//           pattern: /innerHTML\s*=\s*[^;]+\+/g,
//           severity: "high",
//           title: "Potential XSS vulnerability",
//           description: "Direct innerHTML assignment with concatenation can lead to XSS",
//           suggestion: "Use textContent or properly sanitize HTML content",
//           cwe: "CWE-79",
//         },
//         {
//           pattern: /SELECT\s+\*\s+FROM\s+\w+\s+WHERE\s+\w+\s*=\s*['"][^'"]*['"]?\s*\+/gi,
//           severity: "critical",
//           title: "SQL Injection vulnerability",
//           description: "String concatenation in SQL queries can lead to SQL injection",
//           suggestion: "Use parameterized queries or prepared statements",
//           cwe: "CWE-89",
//         },
//         {
//           pattern: /password\s*=\s*['"][^'"]*['"]/gi,
//           severity: "high",
//           title: "Hardcoded password",
//           description: "Hardcoded passwords in source code are a security risk",
//           suggestion: "Use environment variables or secure configuration files",
//           cwe: "CWE-798",
//         },
//         {
//           pattern: /Math\.random$$$$/g,
//           severity: "medium",
//           title: "Weak random number generation",
//           description: "Math.random() is not cryptographically secure",
//           suggestion: "Use crypto.randomBytes() for security-sensitive operations",
//           cwe: "CWE-338",
//         },
//       ],
//       performance: [
//         {
//           pattern: /for\s*$$[^)]*$$\s*{\s*for\s*$$[^)]*$$\s*{/g,
//           severity: "medium",
//           title: "Nested loops detected",
//           description: "Nested loops can cause performance issues with large datasets",
//           suggestion: "Consider optimizing with more efficient algorithms or data structures",
//         },
//         {
//           pattern: /document\.getElementById$$[^)]+$$/g,
//           severity: "low",
//           title: "Repeated DOM queries",
//           description: "Multiple DOM queries can impact performance",
//           suggestion: "Cache DOM elements in variables when used multiple times",
//         },
//         {
//           pattern: /\.forEach$$[^)]*$$\s*{\s*[^}]*\.push\(/g,
//           severity: "low",
//           title: "Inefficient array operation",
//           description: "Using forEach with push can be less efficient than map",
//           suggestion: "Consider using map() instead of forEach() with push()",
//         },
//         {
//           pattern: /new\s+RegExp\(/g,
//           severity: "low",
//           title: "Dynamic regex compilation",
//           description: "Creating regex patterns at runtime can impact performance",
//           suggestion: "Pre-compile regex patterns when possible",
//         },
//       ],
//       style: [
//         {
//           pattern: /var\s+\w+/g,
//           severity: "low",
//           title: "Use of var keyword",
//           description: "var has function scope which can lead to unexpected behavior",
//           suggestion: "Use let or const instead of var for block scoping",
//         },
//         {
//           pattern: /console\.log\(/g,
//           severity: "low",
//           title: "Console.log statement",
//           description: "Console statements should be removed in production code",
//           suggestion: "Remove console.log statements or use a proper logging library",
//         },
//         {
//           pattern: /==\s*[^=]/g,
//           severity: "low",
//           title: "Loose equality comparison",
//           description: "Using == can lead to unexpected type coercion",
//           suggestion: "Use strict equality (===) for more predictable comparisons",
//         },
//         {
//           pattern: /function\s+\w+\s*$$[^)]*$$\s*{\s*$/gm,
//           severity: "low",
//           title: "Missing function documentation",
//           description: "Functions should be documented for better maintainability",
//           suggestion: "Add JSDoc comments to document function parameters and return values",
//         },
//       ],
//       maintainability: [
//         {
//           pattern: /function\s+\w+\s*$$[^)]*$$\s*{[^}]{500,}/g,
//           severity: "medium",
//           title: "Large function detected",
//           description: "Functions with too much code are hard to maintain",
//           suggestion: "Break down large functions into smaller, more focused functions",
//         },
//         {
//           pattern: /if\s*$$[^)]*$$\s*{\s*if\s*$$[^)]*$$\s*{\s*if\s*$$[^)]*$$\s*{/g,
//           severity: "medium",
//           title: "Deep nesting detected",
//           description: "Deeply nested code is hard to read and maintain",
//           suggestion: "Consider using early returns or extracting nested logic into functions",
//         },
//         {
//           pattern: /catch\s*$$[^)]*$$\s*{\s*}/g,
//           severity: "medium",
//           title: "Empty catch block",
//           description: "Empty catch blocks hide errors and make debugging difficult",
//           suggestion: "Add proper error handling or at least log the error",
//         },
//         {
//           pattern: /TODO|FIXME|HACK/gi,
//           severity: "low",
//           title: "Technical debt marker",
//           description: "Code contains technical debt markers",
//           suggestion: "Address technical debt items before production deployment",
//         },
//       ],
//       bugs: [
//         {
//           pattern: /if\s*\([^)]*=\s*[^=]/g,
//           severity: "high",
//           title: "Assignment in condition",
//           description: "Assignment operator used in conditional statement",
//           suggestion: "Use comparison operator (==) instead of assignment (=)",
//         },
//         {
//           pattern: /return\s*;?\s*\n\s*\w+/g,
//           severity: "medium",
//           title: "Unreachable code",
//           description: "Code after return statement will never execute",
//           suggestion: "Remove unreachable code or fix the logic flow",
//         },
//         {
//           pattern: /\[\s*\]\s*==\s*false|\[\s*\]\s*==\s*true/g,
//           severity: "medium",
//           title: "Array comparison with boolean",
//           description: "Comparing arrays with booleans can produce unexpected results",
//           suggestion: "Check array length or use proper comparison methods",
//         },
//       ],
//     }

//     // Language-specific rules
//     this.languageRules = {
//       javascript: {
//         extensions: [".js", ".jsx"],
//         rules: ["security", "performance", "style", "maintainability", "bugs"],
//       },
//       typescript: {
//         extensions: [".ts", ".tsx"],
//         rules: ["security", "performance", "style", "maintainability", "bugs"],
//         specific: [
//           {
//             pattern: /any\s+\w+/g,
//             severity: "medium",
//             title: "Use of any type",
//             description: "Using any defeats the purpose of TypeScript",
//             suggestion: "Use specific types or interfaces instead of any",
//           },
//         ],
//       },
//       python: {
//         extensions: [".py"],
//         rules: ["security", "performance", "style", "maintainability"],
//         specific: [
//           {
//             pattern: /exec\s*\(/g,
//             severity: "critical",
//             title: "Dangerous exec() usage",
//             description: "Using exec() can lead to code injection vulnerabilities",
//             suggestion: "Avoid using exec() with user input",
//           },
//         ],
//       },
//     }
//   }

//   analyzeFile(filePath, content) {
//     const issues = []
//     const lines = content.split("\n")
//     const fileExtension = path.extname(filePath).toLowerCase()

//     // Determine language and applicable rules
//     const language = this.detectLanguage(fileExtension)
//     const applicableRules = this.getApplicableRules(language)

//     // Analyze with general rules
//     applicableRules.forEach((category) => {
//       if (this.rules[category]) {
//         this.rules[category].forEach((rule) => {
//           const foundIssues = this.findIssues(rule, content, filePath, lines)
//           issues.push(...foundIssues)
//         })
//       }
//     })

//     // Analyze with language-specific rules
//     if (language && this.languageRules[language].specific) {
//       this.languageRules[language].specific.forEach((rule) => {
//         const foundIssues = this.findIssues(rule, content, filePath, lines)
//         issues.push(...foundIssues)
//       })
//     }

//     // Additional analysis
//     issues.push(...this.analyzeComplexity(filePath, content, lines))
//     issues.push(...this.analyzeDuplication(filePath, content, lines))

//     return issues
//   }

//   detectLanguage(fileExtension) {
//     for (const [language, config] of Object.entries(this.languageRules)) {
//       if (config.extensions.includes(fileExtension)) {
//         return language
//       }
//     }
//     return null
//   }

//   getApplicableRules(language) {
//     if (language && this.languageRules[language]) {
//       return this.languageRules[language].rules
//     }
//     return ["security", "performance", "style", "maintainability", "bugs"]
//   }

//   findIssues(rule, content, filePath, lines) {
//     const issues = []
//     let match

//     while ((match = rule.pattern.exec(content)) !== null) {
//       const lineNumber = this.getLineNumber(content, match.index)
//       const columnNumber = this.getColumnNumber(content, match.index)

//       issues.push({
//         file_path: filePath,
//         line_number: lineNumber,
//         column_number: columnNumber,
//         severity: rule.severity,
//         category: rule.category || "general",
//         title: rule.title,
//         description: rule.description,
//         suggestion: rule.suggestion,
//         code_snippet: this.getCodeSnippet(lines, lineNumber),
//         fixed_code: this.generateFixedCode(match[0], rule),
//         cwe: rule.cwe || null,
//       })
//     }

//     // Reset regex lastIndex
//     rule.pattern.lastIndex = 0
//     return issues
//   }

//   analyzeComplexity(filePath, content, lines) {
//     const issues = []
//     const functions = this.extractFunctions(content)

//     functions.forEach((func) => {
//       const complexity = this.calculateCyclomaticComplexity(func.body)
//       if (complexity > 10) {
//         issues.push({
//           file_path: filePath,
//           line_number: func.lineNumber,
//           column_number: 1,
//           severity: complexity > 15 ? "high" : "medium",
//           category: "maintainability",
//           title: "High cyclomatic complexity",
//           description: `Function has cyclomatic complexity of ${complexity}`,
//           suggestion: "Break down complex functions into smaller, simpler functions",
//           code_snippet: this.getCodeSnippet(lines, func.lineNumber),
//           fixed_code: "// Consider refactoring this function",
//         })
//       }
//     })

//     return issues
//   }

//   analyzeDuplication(filePath, content, lines) {
//     const issues = []
//     const duplicates = this.findDuplicateCode(content)

//     duplicates.forEach((duplicate) => {
//       issues.push({
//         file_path: filePath,
//         line_number: duplicate.lineNumber,
//         column_number: 1,
//         severity: "medium",
//         category: "maintainability",
//         title: "Code duplication detected",
//         description: `Similar code block found at line ${duplicate.duplicateLineNumber}`,
//         suggestion: "Extract common code into a reusable function",
//         code_snippet: this.getCodeSnippet(lines, duplicate.lineNumber),
//         fixed_code: "// Extract to function: extractedFunction()",
//       })
//     })

//     return issues
//   }

//   extractFunctions(content) {
//     const functions = []
//     const functionRegex = /function\s+(\w+)\s*$$[^)]*$$\s*{/g
//     let match

//     while ((match = functionRegex.exec(content)) !== null) {
//       const lineNumber = this.getLineNumber(content, match.index)
//       const functionStart = match.index
//       const functionEnd = this.findMatchingBrace(content, functionStart)
//       const body = content.substring(functionStart, functionEnd)

//       functions.push({
//         name: match[1],
//         lineNumber,
//         body,
//         start: functionStart,
//         end: functionEnd,
//       })
//     }

//     return functions
//   }

//   calculateCyclomaticComplexity(code) {
//     // Count decision points
//     const decisionPoints = [
//       /if\s*\(/g,
//       /else\s+if\s*\(/g,
//       /while\s*\(/g,
//       /for\s*\(/g,
//       /switch\s*\(/g,
//       /case\s+/g,
//       /catch\s*\(/g,
//       /&&/g,
//       /\|\|/g,
//       /\?/g,
//     ]

//     let complexity = 1 // Base complexity

//     decisionPoints.forEach((pattern) => {
//       const matches = code.match(pattern)
//       if (matches) {
//         complexity += matches.length
//       }
//     })

//     return complexity
//   }

//   findDuplicateCode(content) {
//     // Simple duplicate detection - look for similar line patterns
//     const lines = content.split("\n")
//     const duplicates = []
//     const minLength = 3 // Minimum lines to consider duplication

//     for (let i = 0; i < lines.length - minLength; i++) {
//       for (let j = i + minLength; j < lines.length - minLength; j++) {
//         let matchCount = 0
//         for (let k = 0; k < minLength; k++) {
//           if (lines[i + k].trim() === lines[j + k].trim() && lines[i + k].trim() !== "") {
//             matchCount++
//           }
//         }

//         if (matchCount === minLength) {
//           duplicates.push({
//             lineNumber: i + 1,
//             duplicateLineNumber: j + 1,
//             length: minLength,
//           })
//         }
//       }
//     }

//     return duplicates
//   }

//   findMatchingBrace(content, start) {
//     let braceCount = 0
//     let inString = false
//     let stringChar = ""

//     for (let i = start; i < content.length; i++) {
//       const char = content[i]

//       if (!inString) {
//         if (char === '"' || char === "'") {
//           inString = true
//           stringChar = char
//         } else if (char === "{") {
//           braceCount++
//         } else if (char === "}") {
//           braceCount--
//           if (braceCount === 0) {
//             return i + 1
//           }
//         }
//       } else {
//         if (char === stringChar && content[i - 1] !== "\\") {
//           inString = false
//         }
//       }
//     }

//     return content.length
//   }

//   getLineNumber(content, index) {
//     return content.substring(0, index).split("\n").length
//   }

//   getColumnNumber(content, index) {
//     const lines = content.substring(0, index).split("\n")
//     return lines[lines.length - 1].length + 1
//   }

//   getCodeSnippet(lines, lineNumber, context = 3) {
//     const start = Math.max(0, lineNumber - context - 1)
//     const end = Math.min(lines.length, lineNumber + context)

//     return lines
//       .slice(start, end)
//       .map((line, index) => {
//         const actualLineNumber = start + index + 1
//         const marker = actualLineNumber === lineNumber ? "> " : "  "
//         return `${marker}${actualLineNumber}: ${line}`
//       })
//       .join("\n")
//   }

//   generateFixedCode(originalCode, rule) {
//     // Enhanced fix suggestions
//     if (rule.title.includes("var keyword")) {
//       return originalCode.replace(/var\s+/, "const ")
//     }
//     if (rule.title.includes("Console.log")) {
//       return "// " + originalCode + " // Removed for production"
//     }
//     if (rule.title.includes("Loose equality")) {
//       return originalCode.replace(/==/g, "===")
//     }
//     if (rule.title.includes("Assignment in condition")) {
//       return originalCode.replace(/=/g, "===")
//     }
//     return originalCode + " // TODO: Apply suggested fix"
//   }

//   calculateQualityScore(issues, totalLines) {
//     let score = 100
//     let securityPenalty = 0
//     let performancePenalty = 0
//     let maintainabilityPenalty = 0

//     issues.forEach((issue) => {
//       let penalty = 0
//       switch (issue.severity) {
//         case "critical":
//           penalty = 15
//           break
//         case "high":
//           penalty = 10
//           break
//         case "medium":
//           penalty = 5
//           break
//         case "low":
//           penalty = 2
//           break
//       }

//       score -= penalty

//       // Track category-specific penalties
//       switch (issue.category) {
//         case "security":
//           securityPenalty += penalty
//           break
//         case "performance":
//           performancePenalty += penalty
//           break
//         case "maintainability":
//           maintainabilityPenalty += penalty
//           break
//       }
//     })

//     // Bonus for good practices
//     const issueRate = (issues.length / Math.max(totalLines, 1)) * 100
//     if (issueRate < 1) score += 5 // Less than 1 issue per 100 lines
//     if (securityPenalty === 0) score += 10 // No security issues
//     if (totalLines > 100 && issues.length < 5) score += 5 // Large files with few issues

//     return {
//       overall: Math.max(0, Math.min(100, score)),
//       security: Math.max(0, 100 - securityPenalty),
//       performance: Math.max(0, 100 - performancePenalty),
//       maintainability: Math.max(0, 100 - maintainabilityPenalty),
//     }
//   }

//   generateReport(issues, filePath, content) {
//     const lines = content.split("\n")
//     const qualityScores = this.calculateQualityScore(issues, lines.length)

//     const categoryCounts = issues.reduce((acc, issue) => {
//       acc[issue.category] = (acc[issue.category] || 0) + 1
//       return acc
//     }, {})

//     const severityCounts = issues.reduce((acc, issue) => {
//       acc[issue.severity] = (acc[issue.severity] || 0) + 1
//       return acc
//     }, {})

//     return {
//       filePath,
//       totalLines: lines.length,
//       totalIssues: issues.length,
//       qualityScores,
//       categoryCounts,
//       severityCounts,
//       issues: issues.sort((a, b) => {
//         const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 }
//         return severityOrder[b.severity] - severityOrder[a.severity]
//       }),
//     }
//   }
// }

// module.exports = EnhancedCodeAnalyzer
