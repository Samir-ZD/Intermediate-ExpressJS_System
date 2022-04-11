const nodemailer = require('nodemailer')

//implement transporter using mailtrap service

exports.sendMail = async (options) => {
    //create transporter instance
    const transporter = nodemailer.createTransport({
        host: process.env.EMAIL_HOST,
        port: process.env.EMAIL_PORT,
        auth: {
            user: process.env.EMAIL_USERNAME,
            pass: process.env.EMAIL_PASSWORD
        }
    });
    //define email options
    const mailOptions = {
        from:process.env.FROM_DUMMY,
        to:options.email,
        subject:options.subject,
        text:options.message, 
    }

    //send mail

    await transporter.sendMail(mailOptions)
}