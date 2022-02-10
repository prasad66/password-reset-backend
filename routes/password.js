var express = require('express');
var router = express.Router();
const { user } = require('../config/dbconfig')
const { hashing, hashCompare, createJWT, authenticate, getUser, emailFromToken, sendMail } = require('../utils/util')
const JWTD = require('jwt-decode')
const JWT = require('jsonwebtoken')
var nodemailer = require('nodemailer');
const Crypto = require('crypto')



/* GET users listing. */
router.get('/', function (req, res, next) {
    res.send('password reset');
});

router.post('/register', async (req, res) => {
    const userEmail = req.body.email;
    const password = req.body.password;
    const hashedPassword = await hashing(password);
    const loginUser = await getUser(userEmail)
    if (loginUser) {
        res.status(400).json({ message: 'User already exists' }) //400 for bad request
        return;
    } else {
        const data = await user.create({
            email: userEmail, password: hashedPassword
        });
        res.status(201).json({ message: 'User created successfully' }) // 200 for user creation
    }

})

router.post('/login', async (req, res) => {
    const userEmail = req.body.email;
    const password = req.body.password;
    const loginUser = await getUser(userEmail)
    const id = loginUser?._id.toString();
    if (loginUser) {
        const login = await hashCompare(password, loginUser.password)
        if (login) {
            const token = await createJWT({ userEmail, id }, 'login')
            res.status(200).send({ message: 'Login Successfull', token: token, options: JWTD(token) })
        } else {
            res.status(401).send({ message: 'Login failed. Invalid Password' })
        }
    } else {
        res.status(401).send({ message: 'Login failed. Invalid credentials' })
    }

})

router.post('/authenticate', authenticate, async (req, res) => {
    res.status(200).send({ message: 'Authentication successfull' })
})

router.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    const userFromDB = await getUser(email);
    if (!userFromDB) {
        res.status(403).send({ message: 'User not registered' })
    } else {
        try {
            const string = Crypto.randomBytes(25).toString('hex');
            const doc = await user.findOneAndUpdate({ email: email }, { verifyString: string }, { new: true })
            const resetJWT = await createJWT({ email, string }, 'verify')
            const link = `https://pwd-rst.netlify.app/forgot-password-redirect/${resetJWT}/${string}`
            let sentMail = sendMail(email, link)
            if (sentMail) {
                res.status(200).send({ token: resetJWT });
            } else {
                res.status(500).send({ message: 'Internal server error' })
            }

        } catch (error) {
            const doc = await user.findOneAndUpdate({ email: email }, { verifyString: '' }, { new: true })
            res.status(500).send({ message: 'Internal server error' })
        };

    }
})

router.post('/forgot-password/verify/:token/:string', authenticate, async (req, res) => {
    const token = req.params.token;
    const string = req.params.string;
    try {
        const email = await emailFromToken(token);
        const user = await getUser(email);
        // return
        if (user.verifyString === string)
            res.status(200).send({ message: 'verified', email, token })
        else
            res.status(401).send({ message: 'Error in the Link. Check the link or Try again' })
    } catch (error) {
        res.status(401).send({ message: error?.message })
    }
})

router.post('/reset-password', async (req, res) => {
    const token = req.header('token');
    const { password } = req.body;
    try {

        const email = await emailFromToken(token);
        const hashedPassword = await hashing(password);
        const value = await user.findOneAndUpdate({ email: email }, { password: hashedPassword, verifyString: '' }, { new: true })
        res.status(200).send({ message: 'Password reset successfull' })
    } catch (error) {
        await user.findOneAndUpdate({ email: email }, { verifyString: '' }, { new: true })
        res.status(500).send({ message: 'Error in the server' })
    }
})
module.exports = router;

