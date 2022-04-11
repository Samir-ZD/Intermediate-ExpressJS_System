const express = require("express");
const dotenv = require("dotenv").config();
const DB = require("./database").connectToDb;
const app = express();

const authRouter = require("./routes/authRouter");
const userRouter = require("./routes/userRouter");

// connect to DB server
DB();

app.use(express.json());

app.use("/api/auth", authRouter);
app.use("/api/users", userRouter);

app.listen(process.env.PORT, () => {
  console.log("listening on port " + process.env.PORT);
});