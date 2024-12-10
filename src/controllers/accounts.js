const { ObjectId } = require("mongodb");
const bcrypt = require("bcryptjs");
const { connectToDatabase } = require("../utils/db");

const {
  validateEmail,
  validatePassword,
  encryptData,
  createToken,
  generateCsrfToken,
} = require("../utils");

const signupNewUser = async (req, res) => {
  try {
    const db = await connectToDatabase();
    if (!req.body.password) {
      req.body.password = "P@ssword.1";
    }
    const { email, password } = req.body;
    const csrfToken = generateCsrfToken();

    // Validate email first
    const emailValidation = validateEmail(email);
    if (emailValidation.error) {
      return res.status(400).json({ error: emailValidation.error });
    }

    // Validate password second
    const passwordValidation = validatePassword(password);
    if (passwordValidation.error) {
      return res.status(400).json({ error: passwordValidation.error });
    }

    // Check if email is already in use
    const existingUser = await db.collection("accounts").findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: "Email is taken!" });
    }

    // Encrypt password and continue with user creation logic
    const encryptedPassword = await encryptData("password", password);
    const result = await db.collection("accounts").insertOne({
      ...req.body,
      ...encryptedPassword,
    });

    const token = createToken(result.insertedId);
    await db
      .collection("accounts")
      .updateOne({ _id: new ObjectId(result.insertedId) }, { $set: { token } });

    res.cookie("AuthToken", token, {
      maxAge: 1000 * 60 * 60,
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      // sameSite: "Strict",
    });
    res.cookie("CSRF-TOKEN", csrfToken, {
      maxAge: 1000 * 60 * 60,
      httpOnly: false,
      secure: process.env.NODE_ENV === "production",
      // sameSite: "Strict",
    });

    res.status(201).json({ message: "User created successfully" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

const signinUser = async (req, res) => {
  const csrfToken = generateCsrfToken();
  try {
    const db = await connectToDatabase();
    if (!req.body.password) {
      req.body.password = "P@ssword.1";
    }
    const { email, password } = req.body;
    // Validate email
    const emailValidation = validateEmail(email);
    if (emailValidation.error) {
      return res.status(400).json({ error: emailValidation.error });
    }

    // Validate password before proceeding with the database query
    const passwordValidation = validatePassword(password);
    if (passwordValidation.error) {
      return res.status(400).json({ error: passwordValidation.error });
    }

    const existingUser = await db.collection("accounts").findOne({ email });
    if (existingUser) {
      // Comparing the password after validation
      const validity = await bcrypt.compare(password, existingUser.password);
      if (!validity) {
        return res.status(400).json({ error: "Wrong password" });
      }

      const { _id } = existingUser;
      const token = createToken(_id);
      await db
        .collection("accounts")
        .updateOne({ _id: new ObjectId(_id) }, { $set: { token } });

      res.cookie("AuthToken", token, {
        maxAge: 1000 * 60 * 60,
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        // sameSite: "Strict",
      });
      res.cookie("CSRF-TOKEN", csrfToken, {
        maxAge: 1000 * 60 * 60,
        httpOnly: false,
        secure: process.env.NODE_ENV === "production",
        // sameSite: "Strict",
      });

      return res.status(200).json({ message: "User successfully signed in" });
    } else {
      return res.status(404).json({ error: "Email does not exist" });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

const fetchSingleUser = async (req, res) => {
  const requestedUserId = req.requestedUserId; // Retrieve from req object
  console.log({ requestedUserId });
  if (!requestedUserId) {
    return res.status(400).json({ error: "Requested user ID is missing" });
  }

  try {
    const db = await connectToDatabase();
    const user = await db
      .collection("accounts")
      .findOne({ _id: new ObjectId(requestedUserId) });
    if (user) {
      res.status(200).json(user);
    } else {
      res
        .status(404)
        .json({ error: `Failed to fetch data with id: ${requestedUserId}` });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

const SearchUserByEmailOrByFirstNameAndLastName = async (req, res) => {
  const { email, firstName, lastName } = req.query; // Retrieve query parameters from the request

  if (!email && (!firstName || !lastName)) {
    return res.status(400).json({
      error:
        "Either email or both firstName and lastName must be provided for the search.",
    });
  }

  try {
    const db = await connectToDatabase();

    // Build the query object based on provided parameters
    let query = {};
    if (email) {
      query.email = email;
    } else {
      query.firstName = firstName;
      query.lastName = lastName;
    }

    // Search the user in the database
    const user = await db.collection("accounts").findOne(query);

    if (user) {
      res.status(200).json(user); // Return the user if found
    } else {
      res.status(404).json({
        error: "No user found with the provided email or name combination.",
      });
    }
  } catch (error) {
    console.error("Error searching for user:", error);
    res.status(500).json({ error: error.message });
  }
};

/**
 * UpdateUserRoleAsCoolerKidOrCoolestKid
 * Searches for a user by email or by first name and last name and updates their role.
 */
const UpdateUserRoleAsCoolerKidOrCoolestKid = async (req, res) => {
  const { email, firstName, lastName, role } = req.body;

  // Validate that the role is one of the allowed roles
  const allowedRoles = ["Cool Kid", "Cooler Kid", "Coolest Kid"];
  if (!allowedRoles.includes(role)) {
    return res.status(400).json({
      error:
        "Invalid role provided. Allowed roles are 'Cool Kid', 'Cooler Kid', 'Coolest Kid'.",
    });
  }

  if (!email && (!firstName || !lastName)) {
    return res.status(400).json({
      error:
        "Either email or both firstName and lastName must be provided to update the user's role.",
    });
  }

  try {
    const db = await connectToDatabase();

    // Build the query object based on provided parameters
    let query = {};
    if (email) {
      query.email = email;
    } else {
      query.firstName = firstName;
      query.lastName = lastName;
    }

    // Search the user in the database
    const user = await db.collection("accounts").findOne(query);

    if (user) {
      // Update the user's role in the database
      const updateResult = await db
        .collection("accounts")
        .updateOne(query, { $set: { role: role } });

      if (updateResult.modifiedCount > 0) {
        res.status(200).json({ message: `User's role updated to ${role}.` });
      } else {
        res.status(500).json({ error: "Failed to update the user's role." });
      }
    } else {
      res.status(404).json({
        error: "No user found with the provided email or name combination.",
      });
    }
  } catch (error) {
    console.error("Error updating user role:", error);
    res.status(500).json({ error: error.message });
  }
};

const deleteSingleUser = async (req, res) => {
  const requestedUserId = req.requestedUserId; // Retrieve from req object
  try {
    const db = await connectToDatabase();
    const user = await db
      .collection("accounts")
      .findOneAndDelete({ _id: new ObjectId(requestedUserId) });
    if (user) {
      res.status(200).json({ message: "User successfully deleted" });
    } else {
      res.status(404).json({
        error: `Failed to delete user with with id:${requestedUserId}`,
      });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};
const updateSingleUser = async (req, res) => {
  const requestedUserId = req.requestedUserId; // Retrieve from req object
  try {
    const db = await connectToDatabase();
    const passwordToUpdateTo = req.body.password;
    const emailToUpdateTo = req.body.email;

    // If keys that need validation are present, perform validation and encryption
    if (passwordToUpdateTo || emailToUpdateTo) {
      if (passwordToUpdateTo) {
        const passwordValidation = validatePassword(passwordToUpdateTo);
        if (passwordValidation.error) {
          return res.status(400).json({ error: passwordValidation.error });
        }
        // Encrypt the password
        const encryptedData = await encryptData("password", passwordToUpdateTo);
        if (encryptedData.error) {
          return res.status(500).json({ error: encryptedData.error });
        }
        req.body.password = encryptedData.password;
      }

      if (emailToUpdateTo) {
        // Validate the email format
        const emailValidation = validateEmail(emailToUpdateTo);
        if (emailValidation.error) {
          return res.status(400).json({ error: emailValidation.error });
        }

        // Check if the email is already taken by another user, but not by the user themselves
        const existingUser = await db.collection("accounts").findOne({
          email: emailToUpdateTo,
          _id: { $ne: new ObjectId(requestedUserId) },
        });

        if (existingUser) {
          return res
            .status(400)
            .json({ error: "Email is already taken by another user" });
        }
      }
    }

    // Update the document with the new data (password, email, etc.)
    const updatedUser = await db.collection("accounts").findOneAndUpdate(
      { _id: new ObjectId(requestedUserId) }, // Find the user by their ID
      { $set: req.body } // Set the updated data (password, email, etc.)
    );

    // Check if the user was successfully updated
    if (updatedUser) {
      return res.status(200).json({ message: "User updated successfully" });
    } else {
      return res
        .status(404)
        .json({ error: `Failed to update user with id: ${requestedUserId}` });
    }
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
};

const fetchAllUsersAsCoolerKidOrCoolestKid = async (req, res) => {
  const userRole = req.userRole;

  try {
    const db = await connectToDatabase();
    const users = await db.collection("accounts").find({}).toArray(); // Convert cursor to array

    if (users.length > 0) {
      // Define role-based filters
      const mapUsersForCoolerKid = (user) => {
        const { firstName, lastName, image, country } = user;
        return { firstName, lastName, image, country };
      };

      const mapUsersForCoolestKid = (user) => {
        const { firstName, lastName, image, email, role, country } = user;
        return { firstName, lastName, email, image, role, country };
      };

      // Apply role-based filtering
      let filteredUsers;
      if (userRole === "Cooler Kid") {
        filteredUsers = users.map(mapUsersForCoolerKid);
      } else if (userRole === "Coolest Kid") {
        filteredUsers = users.map(mapUsersForCoolestKid);
      } else {
        return res.status(403).json({ error: "Unauthorized" });
      }

      // Respond with filtered data
      res.status(200).json(filteredUsers);
    } else {
      res.status(404).json({ error: "No users found" });
    }
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ error: error.message });
  }
};
module.exports = {
  signupNewUser,
  fetchSingleUser,
  fetchAllUsersAsCoolerKidOrCoolestKid,
  deleteSingleUser,
  updateSingleUser,
  SearchUserByEmailOrByFirstNameAndLastName,
  UpdateUserRoleAsCoolerKidOrCoolestKid,
  signinUser,
};
