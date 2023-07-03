const { JWT_SECRET } = require("../secrets"); // use this secret!
const jwt = require("jsonwebtoken")
const Users = require("../users/users-model")

const restricted = (req, res, next) => {
  const token = req.headers.authorization
  if (token) {
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
      if (err) {
        next({status: 401, message: "Token invalid"})
      } else {
        req.decodedJwt = decoded
        next()
      }
    })
  } else {
    next({status: 401, message: "Token required"})
  }
}

const only = role_name => (req, res, next) => {
  if (req.decodedJwt && req.decodedJwt.role_name === role_name) {
    next()
  } else next({status: 403, message: "This is not for you"})



  /*
    If the user does not provide a token in the Authorization header with a role_name
    inside its payload matching the role_name passed to this function as its argument:
    status 403
    {
      "message": "This is not for you"
    }

    Pull the decoded token from the req object, to avoid verifying it again!
  */
}


const checkUsernameExists = async (req, res, next) => {
  const { username } = req.body
  const user = await Users.findBy({ username })
  
  if (user.length === 0) {
    next({ status: 401, message: "Invalid credentials"})
  }
  next()
}

const validateRoleName = (req, res, next) => {
    if (!req.body.role_name) {
      req.body.role_name = 'student'
    }
    
    req.role_name = req.body.role_name.trim();
      
    if (req.role_name === 'admin') {
        next({ status: 422, message: "Role name can not be admin"})
    } else if (req.role_name.length > 32) {
      next({ status: 422, message: "Role name can not be longer than 32 chars"})
    }
    
    next()
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
