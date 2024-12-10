const express = require("express");
const {
  authenticate,
  authenticateCoolerOrCoolestKid,
} = require("../utils/index.js");

const {
  signupNewUser,
  signinUser,
  updateSingleUser,
  fetchSingleUser,
  deleteSingleUser,
  fetchAllUsersAsCoolerKidOrCoolestKid,
  UpdateUserRoleAsCoolerKidOrCoolestKid,
} = require("../controllers/accounts.js");

const router = express.Router();

//Authentication Middleware being applied globally

//creating new user
router.post("/signup", authenticate, signupNewUser);

//logging in user
router.post("/signin", authenticate, signinUser);

//updating user by self
router.put("/update", authenticate, updateSingleUser);

//role update by Cooler or Coolest kid
router.put(
  "/role-update",
  authenticateCoolerOrCoolestKid,
  UpdateUserRoleAsCoolerKidOrCoolestKid
);

//delete user by self
router.delete("/delete", authenticate, deleteSingleUser);

//fetch single user by self
router.get("/user", authenticate, fetchSingleUser);

//fetch all users by Cooler or Coolest Kid
router.get(
  "/users",
  authenticateCoolerOrCoolestKid,
  fetchAllUsersAsCoolerKidOrCoolestKid
);

module.exports = router;
