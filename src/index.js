const express = require("express");
require("dotenv").config();
const bodyParser = require("body-parser");
const { MongoClient } = require("mongodb");
const cookieParser = require("cookie-parser");
const cors = require("cors");

const app = express();
app.use(bodyParser.json({ limit: "50mb", extended: true }));
app.use(bodyParser.urlencoded({ limit: "50mb", extended: true }));
// CORS and BodyParser setup
const corsOptions = {
  origin: ["http://localhost:3001", "http://localhost:3000"],
  methods: "GET,HEAD,PUT,PATCH,POST,DELETE",
  credentials: true,
  optionsSuccessStatus: 204,
};
app.use(cors(corsOptions));
app.use(cookieParser());

// MongoDB connection
const uri = process.env.MONGO_URI;
const client = new MongoClient(uri);

async function startServer() {
  try {
    await client.connect();
    // console.log("Connected to the database");

    const server = app.listen(process.env.PORT || 5000, () => {
      console.log("App is running on port", process.env.PORT || 5000);
    });

    server.timeout = 30000;

    process.on("SIGINT", () => {
      console.log("Shutting down server gracefully...");
      server.close(() => {
        client.close();
        console.log("Server and DB connection closed.");
        process.exit(0);
      });
    });
  } catch (error) {
    console.error("Error connecting to the database:", error);
    process.exit(1); // Exit process with failure
  }
}

startServer();

// Global error handler
// app.use((err, req, res) => {
//   console.error(err);
//   res.status(500).json({ error: "Internal Server Error" });
// });

// Routes
const accounts = require("./routes");
app.use("/", accounts);
module.exports = app;
