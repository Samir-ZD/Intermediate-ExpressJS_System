const jwt = require('jsonwebtoken')
const validator = require('validator');
const User = require('../models/userModel')
const { promisify } = require('util');
const sendMail = require('../utils/email').sendMail;
const crypto = require('crypto')


//Assigning JWT
const signToken = (id) => {
    return jwt.sign({ id }, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRES_IN
    });
};

//Helper function
const createSendToken = (user, statusCode, res) => {
    const token = signToken(user._id);
    res.status(statusCode).json({
        status: "Success",
        token,
        data: {
            user
        }
    });
}

exports.signup = async (req, res) => {
    try {
        const userEmailCheck = await User.findOne({ email: req.body.email })
        if (userEmailCheck) {
            return res.status(409).json({ message: "Email Already in Use" })
        }
        if (!validator.isEmail(req.body.email)) {
            return res.status(400).json({ message: "Please Enter a Valid Email" })
        }
        if (req.body.password !== req.body.passwordConfirm) {
            return res.status(409).json({ message: "Passwords Doesn't Match" })
        }

        const createNewUser = await user.create(req.body)
        createSendToken(createNewUser, 201, res)
    } catch (err) {
        res.status(400).json({ message: err.message })
    }
};

exports.login = async (req, res) => {
    try {
        const { email, password } = req.body
        const user = await User.findOne({ email: req.body.email })
        if (!user || !(await user.checkPassword(password, user.password))) {
            return res.status(401).json({ message: "Incorrect Email or Password" })
        }
        return createSendToken(user, 200, res)
    } catch (err) {
        res.status(400).json({ message: err.message })

    }
};

//Protect Routes
exports.protect = async (req, res, next) => {
    try {

        //Check if User Token exits,else->login again
        let token;
        if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
            token = req.headers.authorization.split(" ")[1]
        }
        if (!token) {
            return res.status(401).json({ message: "You Are Not Logged-in, Please Login" })
        }
        //Verify Token and decode(check if used before)
        let decoded;
        try {
            decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET)
        } catch (err) {
            if (err.name === 'JsonWebTokenError') {
                return res.status(401).json({ message: "Invalid Token,Please Login" })
            } else if (err.name === "TokenExpiredError") {
                return res.status(401).json({ message: "Your Session is Expired,Please Login Again" })
            }
        }
        //Check if User Still Exist
        const currentUser = await User.findById(decoded.id);
        if (!currentUser) {
            return res.status(401).json({ message: "User Doesnt Exist" })
        }
        //check if user changed password, after token created
        if (currentUser.passwordChangedAfterTokenIssued(decoded.iat)) {
            return res.status(401).json({ message: "Please Login again" })
        }

        req.user = currentUser; // verify valid user with sub request(as enitializing session) 
        next();//call next middelware
    } catch (err) {
        console.log(err)
    }
}

//Generate Temporary token to redirect user to reset page 
exports.forgotPassword = async (req, res) => {
    try {
        const user = await User.findOne({ email: req.body.email })
        if (!user) {
            return res.status(401).json({ message: "This User Doesn't Exist" })
        }

        const resetToken = user.generatePasswordResetToken();
        await user.save({ validateBeforeSave: false })//no need to revalidate

        //send reset password email
        //ex: http://Domain/api/resetpassword/token/

        const url = `${req.protocol}://${req.get("host")}/api/auth/resetPassword/${resetToken}`;
        const msg = `Please Follow the following link to Reset Your password: ${url}`;

        try {
            await sendMail({
                email: user.email,
                subject: "Your Password Reset Token, Valid for 10 minutes",
                message: msg
            });
            return res.status(200).json({ message: "Reset Token Successfully Sent to Your Email Adresse" })

        } catch (err) {
            user.passwordResetToken = undefined;
            user.passwordResetExpires = undefined;
            await User.save({ validateBeforeSave: false })//no need to revalidate
            return res.status(500).json({ message: "Error Occured While Sending The Email, Please Try Again Later" })

        }

    } catch (err) {
        console.log(err)
    }
}

// reset user password after successful redirection
exports.resetPassword = async (req, res) => {
    try {
        //encryt password to campare with ENCRYPTED passowrd in DB

        const hashtoken = crypto.createHash("sha256").update(req.params.token).digest("hex");

        const user = await User.findOne({
            passwordResetToken: hashtoken,
            passwordResetExpires: { $gt: Date.now() },
        });

        if (!user) {
            return res.status(400).json({
                message:
                    " The Token is Invalid or Expired. Please Submit Another Request",
            });
        }

        if (req.body.password.length < 8) {
            return res.status(400).json({
                message: "Password Length Must be at Least 8 Characters",
            });
        }

        if (req.body.password !== req.body.passwordConfirm) {
            return res.status(400).json({
                message: "Password and PasswordConfirm Does Not Match",
            });
        }

        user.password = req.body.password;
        user.passwordConfirm = req.body.passwordConfirm;
        user.passwordResetToken = undefined;
        user.passwordResetExpires = undefined;

        await user.save();
        //provide new JWT to user

        createSendToken(user, 200, res);
    } catch (err) {
        console.log(err);
    }
};
