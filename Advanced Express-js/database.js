const mongoose = require("mongoose");
const dotenv = require("dotenv").config();

exports.connectToDb = async () => {
  try {
    await mongoose.connect(process.env.DB_URL);
    console.log("Connected to Database.");
  } catch (err) {
    console.log(err);
    process.exit(1);
  }
};