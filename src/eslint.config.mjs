import globals from "globals";
import pluginJs from "@eslint/js";

/** @type {import('eslint').Linter.FlatConfig[]} */
export default [
  {
    files: ["**/*.js"],
    languageOptions: {
      sourceType: "commonjs", // Set to commonjs for Node.js modules
      globals: {
        ...globals.browser, // Include browser globals
        process: "readonly", // Define process as a readonly global for Node.js
        ...globals.jest, // Add Jest globals to avoid undefined errors for test and expect
      },
    },
    rules: {
      "no-unused-vars": "off",
    },
  },
  {
    languageOptions: {
      globals: globals.browser, // Ensure the browser globals are set
    },
    ...pluginJs.configs.recommended,
  },
];
