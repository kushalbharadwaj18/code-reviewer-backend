// const axios = require("axios")

// class GitHubIntegration {
//   constructor(accessToken) {
//     this.accessToken = accessToken
//     this.apiBase = "https://api.github.com"
//   }

//   async getRepositories(username) {
//     try {
//       const response = await axios.get(`${this.apiBase}/users/${username}/repos`, {
//         headers: {
//           Authorization: `token ${this.accessToken}`,
//           Accept: "application/vnd.github.v3+json",
//         },
//       })
//       return response.data
//     } catch (error) {
//       throw new Error("Failed to fetch repositories")
//     }
//   }

//   async getRepositoryContents(owner, repo, path = "", branch = "main") {
//     try {
//       const response = await axios.get(`${this.apiBase}/repos/${owner}/${repo}/contents/${path}`, {
//         headers: {
//           Authorization: `token ${this.accessToken}`,
//           Accept: "application/vnd.github.v3+json",
//         },
//         params: { ref: branch },
//       })
//       return response.data
//     } catch (error) {
//       throw new Error("Failed to fetch repository contents")
//     }
//   }

//   async getFileContent(owner, repo, path, branch = "main") {
//     try {
//       const response = await axios.get(`${this.apiBase}/repos/${owner}/${repo}/contents/${path}`, {
//         headers: {
//           Authorization: `token ${this.accessToken}`,
//           Accept: "application/vnd.github.v3+json",
//         },
//         params: { ref: branch },
//       })

//       if (response.data.encoding === "base64") {
//         return Buffer.from(response.data.content, "base64").toString("utf-8")
//       }
//       return response.data.content
//     } catch (error) {
//       throw new Error("Failed to fetch file content")
//     }
//   }

//   async createPullRequestComment(owner, repo, pullNumber, body, path, line) {
//     try {
//       const response = await axios.post(
//         `${this.apiBase}/repos/${owner}/${repo}/pulls/${pullNumber}/comments`,
//         {
//           body,
//           path,
//           line,
//         },
//         {
//           headers: {
//             Authorization: `token ${this.accessToken}`,
//             Accept: "application/vnd.github.v3+json",
//           },
//         },
//       )
//       return response.data
//     } catch (error) {
//       throw new Error("Failed to create pull request comment")
//     }
//   }

//   async getBranches(owner, repo) {
//     try {
//       const response = await axios.get(`${this.apiBase}/repos/${owner}/${repo}/branches`, {
//         headers: {
//           Authorization: `token ${this.accessToken}`,
//           Accept: "application/vnd.github.v3+json",
//         },
//       })
//       return response.data
//     } catch (error) {
//       throw new Error("Failed to fetch branches")
//     }
//   }
// }

// module.exports = GitHubIntegration
