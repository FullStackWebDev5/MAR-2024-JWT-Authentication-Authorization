const express = require('express')
const bodyParser = require('body-parser')
const mongoose = require('mongoose')
var cors = require('cors')
const dotenv = require('dotenv')
dotenv.config()
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express()

app.use(cors())
app.use(bodyParser.urlencoded())
app.use(bodyParser.json())

const User = mongoose.model('User', {
  firstName: String,
  lastName: String,
  email: String,
  password: String,
  isAdmin: Boolean,
  isPremium: Boolean
})

const isUserLoggedIn = (req, res, next) => {
  try {
    const user = jwt.verify(req.headers.token, process.env.JWT_PRIVATE_KEY);
    req.user = user
    next()
  } catch(error) {
    return res.json({
      message: "You've not logged in! Please log in first!"
    })
  }
}

const isUserPremium = (req, res, next) => {
  if(!req.user.isPremium) {
    return res.json({
      message: "You're not a premium user. Please upgrade your plan to access this page!"
    })
  }
  next()
}


const isUserAdmin = (req, res, next) => {
  if(!req.user.isAdmin) {
    return res.json({
      message: "You're not authorized to access this page!"
    })
  }
  next()
}

// PUBLIC ROUTES
app.get('/', (req, res) => {
  res.json({
    status: 'Server is up :)',
    now: new Date()
  })
})

app.get('/users', async (req, res) => {
  try {
    const users = await User.find();
    res.json({
      status: 'SUCCESS',
      data: users
    })
  } catch (error) {
    res.status(500).json({
      status: 'FAILED',
      message: 'Something went wrong'
    })
  }
})

app.post('/users/signup', async (req, res) => {
  try {
    const { firstName, lastName, email, password, isAdmin, isPremium } = req.body

    const encryptedPassword = await bcrypt.hash(password, 10)

    await User.create({ firstName, lastName, email, password: encryptedPassword,  isAdmin, isPremium } );
    res.json({
      status: 'SUCCESS',
      message: 'User signed up successfully'
    })
  } catch (error) {
    res.status(500).json({
      status: 'FAILED',
      message: 'Something went wrong'
    })
  }
})

app.post('/users/login', async (req, res) => {
  try {
    const { email, password } = req.body
    const user = await User.findOne({ email }).lean()

    if(!user) {
      return res.json({
        status: 'FAILED',
        message: 'Incorrect credentials. Please try again!'
      })
    }

    const match = await bcrypt.compare(password, user.password);

    if(!match) {
      return res.json({
        status: 'FAILED',
        message: 'Incorrect credentials. Please try again!'
      })
    }

    const token = jwt.sign(user, process.env.JWT_PRIVATE_KEY, { expiresIn: 30 });

    res.json({
      status: 'SUCCESS',
      message: 'User logged in successfully',
      token
    })
  } catch (error) {
    res.status(500).json({
      status: 'FAILED',
      message: 'Something went wrong'
    })
  }
})

// PRIVATE ROUTES
// Logged-in users
app.get('/profile', isUserLoggedIn, (req, res) => {
  res.send('PROFILE PAGE')
})

// Premium users
app.get('/premium', isUserLoggedIn, isUserPremium, (req, res) => {
  res.send('PREMIUM PAGE')
})

// Admin users
app.get('/admin', isUserLoggedIn, isUserAdmin, (req, res) => {
  res.send('ADMIN PAGE')
})

app.listen(3000, () => {
  mongoose.connect(process.env.MONGODB_URL)
  .then(() => console.log('Server is running :)'))
  .catch((error) => console.log(error))
})



/*
  # Authentication and Authorization
    - Authentication: Who are you?
    - Authorization: What access do you have?

    - Private Route
      - Can be accessed only by logged in users (Authentication)
      - Can be accessed only by authorized users (Authorization)
        - Admin Dashboard
        - Premium Content

  # Encryption/ Decrytion
    - Encryption: Original password -> Encrypted password
    - Decryption: Encrypted password -> Original password

    - Eg.:
      - Encryption rule: N+3
        - Original password: rohan123
        - Encrypted password: urkdq456
      - Decryption rule: N-3
        - Encrypted password: urkdq456
        - Original password: rohan123

  # Packages:
    - bcrypt
    - jsonwebtoken
*/