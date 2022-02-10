const bcrypt = require('bcryptjs');
const JWT = require('jsonwebtoken');
const JWTD = require('jwt-decode');
const { user } = require('../config/dbconfig')
var nodemailer = require('nodemailer');
const secret = process.env.SECRET_KEY;

const hashing = async (password) => {

    try {
        const salt = await bcrypt.genSaltSync(10);
        const hash = await bcrypt.hashSync(password, salt);
        return hash;
    } catch (error) {
        return error
    }

}

const hashCompare = async (password, hashValue) => {
    try {
        return await bcrypt.compare(password, hashValue);
    } catch (error) {
        return error;
    }
}

const createJWT = async (user, payload) => {
    // const user = { email: userEmail, id: id };
    const time = payload === 'login' ? '30m' : '15m'
    return await JWT.sign(user, secret, { expiresIn: time })
}

const authenticate = async (req, res, next) => {
    const token = req.header('token');
    await JWT.verify(token, secret, (err, payload) => {
        if (err) {
            console.log(err.message)
            return res.status(401).send({ error: err.message });
        }
        next();
    });

}


const getUser = async (email) => {
    return await user.findOne({ email: email })
}

const emailFromToken = async (token) => {
    try {
        const email = await JWTD(token, secret)?.email
        return email;
    } catch (error) {
        console.log(error)
        return;
    }

}

const sendMail = (to, link) => {
    try {
        var transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.MAIL_USER,
                pass: process.env.MAIL_KEY
            }
        });

        var mailOptions = {
            from: {
                name: 'Admin',
                address: 'admin@passwordreset.com',
            },
            to: to,
            subject: 'Password Reset',
            text: `<p>${link}</p>`,
            html: `
        <!doctype html>
        <html lang="en-US">
        
        <head>
            <meta content="text/html; charset=utf-8" http-equiv="Content-Type" />
            <title>Reset Password Email Template</title>
            <meta name="description" content="Reset Password Email Template.">
            <style type="text/css">
                a:hover {text-decoration: underline !important;}
            </style>
        </head>
        
        <body marginheight="0" topmargin="0" marginwidth="0" style="margin: 0px; background-color: #f2f3f8;" leftmargin="0">
            <!--100% body table-->
            <table cellspacing="0" border="0" cellpadding="0" width="100%" bgcolor="#f2f3f8"
                style="@import url(https://fonts.googleapis.com/css?family=Rubik:300,400,500,700|Open+Sans:300,400,600,700); font-family: 'Open Sans', sans-serif;">
                <tr>
                    <td>
                        <table style="background-color: #f2f3f8; max-width:670px;  margin:0 auto;" width="100%" border="0"
                            align="center" cellpadding="0" cellspacing="0">
                            <tr>
                                <td style="height:80px;">&nbsp;</td>
                            </tr>
                            <tr>
                                <td style="height:20px;">&nbsp;</td>
                            </tr>
                            <tr>
                                <td>
                                    <table width="95%" border="0" align="center" cellpadding="0" cellspacing="0"
                                        style="max-width:670px;background:#fff; border-radius:3px; text-align:center;-webkit-box-shadow:0 6px 18px 0 rgba(0,0,0,.06);-moz-box-shadow:0 6px 18px 0 rgba(0,0,0,.06);box-shadow:0 6px 18px 0 rgba(0,0,0,.06);">
                                        <tr>
                                            <td style="height:40px;">&nbsp;</td>
                                        </tr>
                                        <tr>
                                            <td style="padding:0 35px;">
                                                <h1 style="color:#1e1e2d; font-weight:500; margin:0;font-size:32px;font-family:'Rubik',sans-serif;">You have
                                                    requested to reset your password</h1>
                                                <span
                                                    style="display:inline-block; vertical-align:middle; margin:29px 0 26px; border-bottom:1px solid #cecece; width:100px;"></span>
                                                <p style="color:#455056; font-size:15px;line-height:24px; margin:0;">
                                                   To reset your password, copy and go to the link below or click the button. <br /> <br />
                                                   <b>The link is valid only for 15mins.</b> <br /><br />

                                                   ${link}


                                                </p>
                                                <a href="${link}"
                                                    style="background:#20e277;text-decoration:none !important; font-weight:500; margin-top:35px; color:#fff;text-transform:uppercase; font-size:14px;padding:10px 24px;display:inline-block;border-radius:50px;">Reset
                                                    Password</a>
                                            </td>
                                        </tr>
                                        <tr>
                                            <td style="height:40px;">&nbsp;</td>
                                        </tr>
                                    </table>
                                </td>
                            <tr>
                                <td style="height:20px;">&nbsp;</td>
                            </tr>
                            <tr>
                                <td style="height:80px;">&nbsp;</td>
                            </tr>
                        </table>
                    </td>
                </tr>
            </table>
            <!--/100% body table-->
        </body>
        
        </html>`,
            headers: {
                "x-priority": "1",
                "x-msmail-priority": "High",
                importance: "high"
            }
        };

        transporter.sendMail(mailOptions, function (error, info) {
            if (error) {
                return false;
            } else {
                return true;
            }
        });
    } catch (error) {
        return false;
    }
    console.log('mail sent')
    return true;
}

module.exports = { hashing, hashCompare, createJWT, authenticate, getUser, emailFromToken, sendMail }