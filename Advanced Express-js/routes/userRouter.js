const express = require('express')
const router = express.Router()

const userController = require('../controllers/userController')
const authController = require('../controllers/authController')


router.get("/allusers",authController.protect,userController.getAllUsers)


module.exports = router