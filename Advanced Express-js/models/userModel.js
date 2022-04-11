const mongoose = require('mongoose')
const bcrypt = require('bcrypt');
const crypto = require('crypto')

const userSchema = new mongoose.Schema(
    {
        name: {
            type: String,
            required: [true, "Please Enter Your Name."],
            maxlength: 15,
            trim: true
        },
        email: {
            type: String,
            required: [true, "Please Enter Your Email"],
            trim: true
        },
        role:{
            type:String,
            default:"user",
            enum:["admin","ceo","user"],
        },
        password: {
            type: String,
            required: [true, "Please Enter Your Password"],
            trim: true,
            minlength: 6
        },
        passwordConfirm: {
            type: String,
            required: [true, "Please Enter Your Password"],
            trim: true,
            minlength: 6
        },
        passwordChangedAt: Date,
        passwordResetToken: String,
        passwordResetExpires: Date
    },
    {
        timestamps: true
    })

//Automation to Save Operations on triggered function
userSchema.pre("save", async function (next) {
    try {
        //check if password is in req.body -> Hash
        if (!this.isModified("password")) {
            return next();//middleware
        }
        this.password = await bcrypt.hash(this.password, 12)
        this.passwordConfirm = undefined;
    } catch (err) {
        console.log(err)
    }
});

userSchema.methods.checkPassword = async function (
    candidatePassword, // inside form
    userPassword // inside DB
) {
    return await bcrypt.compare(candidatePassword, userPassword);
};

//Automation to change passwordChangedAT after Save operation 
userSchema.pre("save", function (next) {
    if (this.isModified('password') || this.isNew) {
        return next;
    }
    this.passwordChangedAt = Date.now() - 1000;
    next();
})

//if user chaneged password-> login again 
userSchema.methods.passwordChangedAfterTokenIssued = function (jwtTimestap) {

    if (this.passwordChangedAt) {
        const passwordChangeTime = parseInt(this.passwordChangedAt.getTime() / 1000, 10);
        return passwordChangeTime > jwtTimestap;
    }
    return false;
}

userSchema.methods.generatePasswordResetToken = function () {
    const resetToken = crypto.randomBytes(32).toString('hex')

    this.passwordResetToken = crypto.createHash('sha256').update(resetToken).digest('hex')
    this.passwordResetExpires = Date.now() + 10 * 60 * 1000 //10mins

    return resetToken;
}

module.exports = mongoose.model("User", userSchema);