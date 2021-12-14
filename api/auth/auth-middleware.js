const jwt = require('jsonwebtoken')
const { JWT_SECRET } = require('../secrets') // use this secret!

const Users = require('../users/users-model')

const restricted = (req, res, next) => {
  const token = req.headers.authorization

  if (!token) {
    return next({ status: 401, message: 'Token required' })
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return next({ status: 401, message: 'Token invalid' })
    }

    req.decodedJwt = decoded
    next()
  })
}

const only = (role_name) => (req, res, next) => {
  if (req.decodedJwt.role_name === role_name) {
    next()
  } else {
    next({ status: 403, message: 'This is not for you' })
  }
}

const checkUsernameExists = (req, res, next) => {
  const { username } = req.body
  Users.findBy({ username })
    .then(([user]) => {
      if (!user) {
        return next({ status: 401, message: 'Invalid credentials' })
      }

      next()
    })
    .catch(next)
}

const validateRoleName = (req, res, next) => {
  let { role_name } = req.body

  if (!role_name || !role_name.trim()) {
    req.role_name = 'student'
    return next()
  }

  role_name = role_name.trim()

  if (role_name === 'admin') {
    return next({ status: 422, message: 'Role name can not be admin' })
  }

  if (role_name.length > 32) {
    return next({ status: 422, message: 'Role name can not be longer than 32 chars' })
  }

  req.role_name = role_name
  next()
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
