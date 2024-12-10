const request = require("supertest");
const app = require("../index");

test("POST /signup should return 400 if email is invalid", async () => {
  const response = await request(app)
    .post("/signup")
    .send({ email: "invalidemail", password: "P@ssword.1" });

  expect(response.status).toBe(400);
  expect(response.body.error).toBe("Invalid email format");
});

test("POST /signup should return 400 if password is invalid", async () => {
  const response = await request(app)
    .post("/signup")
    .send({ email: "validemail@example.com", password: "123" }); // Short password

  expect(response.status).toBe(400);
  expect(response.body.error).toBe(
    "Password must be at least 6 characters long"
  );
});

test("POST /signup should return 400 if email is already taken", async () => {
  const email = "test@example.com"; // this email is already taken
  const response = await request(app)
    .post("/signup")
    .send({ email, password: "P@ssword.1" });

  expect(response.status).toBe(400);
  expect(response.body.error).toBe("Email is taken!");
});

test("POST /signup should create a new user", async () => {
  const response = await request(app)
    .post("/signup")
    .send({ email: "newuser@example.com", password: "P@ssword.1" });

  expect(response.status).toBe(201);
  expect(response.body).toEqual({ message: "User created successfully" });
});
