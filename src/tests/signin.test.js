const request = require("supertest");
const app = require("../index");

test("POST /signin should return 400 if email is invalid", async () => {
  const response = await request(app)
    .post("/signin")
    .send({ email: "invalidemail", password: "P@ssword.1" });

  expect(response.status).toBe(400);
  expect(response.body.error).toBe("Invalid email format");
});

test("POST /signin should return 400 if password is invalid", async () => {
  const response = await request(app)
    .post("/signin")
    .send({ email: "validemail@example.com", password: "123" }); // Short password

  expect(response.status).toBe(400);
  expect(response.body.error).toBe(
    "Password must be at least 6 characters long"
  );
});

test("POST /signin should return 404 if email does not exist", async () => {
  const response = await request(app)
    .post("/signin")
    .send({ email: "nonexistent@example.com", password: "P@ssword.1" });

  expect(response.status).toBe(404);
  expect(response.body.error).toBe("Email does not exist");
});

test("POST /signin should return 400 if the password is valid but incorrect", async () => {
  const response = await request(app)
    .post("/signin")
    .send({ email: "test@example.com", password: "P@sssword.1" }); // Valid format, but wrong password

  expect(response.status).toBe(400);
  expect(response.body.error).toBe("Wrong password");
});

test("POST /signin should return 400 if the password format is invalid", async () => {
  const response = await request(app)
    .post("/signin")
    .send({ email: "test@example.com", password: "123" }); // Invalid password format (too short)

  expect(response.status).toBe(400);
  expect(response.body.error).toBe(
    "Password must be at least 6 characters long"
  );
});

test("POST /signin should successfully sign in the user", async () => {
  const response = await request(app)
    .post("/signin")
    .send({ email: "test@example.com", password: "P@ssword.1" });

  expect(response.status).toBe(200);
  expect(response.body.message).toBe("User successfully signed in");
  expect(response.headers["set-cookie"]).toBeDefined(); // Check cookies are set
});
