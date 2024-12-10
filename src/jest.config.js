// jest.config.js
module.exports = {
  testEnvironment: "node",
  setupFiles: ["dotenv/config"], // Ensure dotenv is loaded
  testPathIgnorePatterns: ["/node_modules/", "/dist/"], // Ignore unnecessary paths
  coverageDirectory: "./coverage", // Directory to store coverage reports
  collectCoverage: true, // Collect test coverage data
  setupFilesAfterEnv: ["./jest.setup.js"],
};
