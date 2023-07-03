const router = require("express").Router();
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!
const Users = require("../users/users-model")

router.post("/register", validateRoleName, (req, res, next) => {
  const { username, password } = req.body
  const hash = bcrypt.hashSync(password, 12)

  Users.add({ username, password: hash, role_name: req.role_name})
    .then(newUser => {
      res.status(201).json(newUser)
    })
    .catch(next)
});

router.post("/login", checkUsernameExists, (req, res, next) => {

  const { username, password } = req.body;

  Users.findBy({ username })
    .then(([user]) => {
      if (user && bcrypt.compareSync(password, user.password)) {
        const token = tokenBuilder(user)
        res.status(200).json({
          message: `${username} is back!`,
          token: token
        })
      } else {
        next({status: 401, message: "Invalid credentials"})
      }
    })
});

function tokenBuilder(user) {
  const payload = {
    subject: user.user_id,
    username: user.username,
    role_name: user.role_name
  }
  const options = {
    expiresIn: '1d'
  }
  return jwt.sign(payload, JWT_SECRET, options)
}


module.exports = router;
