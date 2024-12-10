const mongodb = require("mongodb");
const MongoClient = mongodb.MongoClient;
require("dotenv").config();
const connectionString = process.env.MONGO_URI || "";
const client = new MongoClient(connectionString);

// Function to connect to the database
const connectToDatabase = async () => {
  try {
    await client.connect();
    return client.db("user-accounts"); // return the database connection
  } catch (error) {
    console.error("MongoDB connection error in controller:", error.message); // fixed the typo
    throw error; // rethrow the error to handle it outside the function
  }
};

// Export the connectToDatabase function for use elsewhere
module.exports = { connectToDatabase };
