// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!
const express = require('express');
const Auth = require('./auth-middleware');
const router = express.Router();
const Users = require("../users/users-model")
const bcrypt = require('bcryptjs');

router.post('/register', Auth.checkPasswordLength, Auth.checkUsernameFree, async (req, res, next) => {
  const {username, password} = req.body;
  const hashedpass = bcrypt.hashSync(password, 8)
  try {
    const newUser = await Users.add({username, password: hashedpass})
    res.status(201).json(newUser);
  } catch (error) {
    next({status: 500, message: "Internal server error", error})
  }
});

/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "user_id": 2,
    "username": "sue"
  }

  response on username taken:
  status 422
  {
    "message": "Username taken"
  }

  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */


router.post('/login', Auth.checkUsernameExists, async (req, res, next) => {
  const password = req.body.password;
  if (bcrypt.compareSync(password, req.user.password)) {
    req.session.user = req.user
    res.json({message: `Welcome ${req.user.username}`})
  } else {
    next({status: 401, message: "invalid credentials"})
  }

})
/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */


/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */

router.get('/logout', async (req, res, next) => {
  if (!req.session.user) {
    res.json({message: 'no session'})
  } else (
    req.session.destroy(error => {
      if (error) {
        next(error)
      } else {
        res.json({message: 'logged out'})
      }
    })

  )
})

 
// Don't forget to add the router to the `exports` object so it can be required in other modules

module.exports = router;