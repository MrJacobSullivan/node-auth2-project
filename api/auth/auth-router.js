const router = require('express').Router()
const bcrypt = require('bcryptjs')
const { BCRYPT_ROUNDS } = require('../../config')

const { checkUsernameExists, validateRoleName } = require('./auth-middleware')

const { tokenBuilder } = require('./auth-helpers')

const Users = require('../users/users-model')

router.post('/register', validateRoleName, (req, res, next) => {
  const user = req.body
  const hash = bcrypt.hashSync(user.password, BCRYPT_ROUNDS)
  user.password = hash

  Users.add({ ...user, role_name: req.role_name })
    .then((saved) => {
      res.status(201).json(saved)
    })
    .catch(next)
})

router.post('/login', checkUsernameExists, (req, res, next) => {
  const { username, password } = req.body

  Users.findBy({ username })
    .then(([user]) => {
      if (user && bcrypt.compareSync(password, user.password)) {
        const token = tokenBuilder(user)

        return res.status(200).json({
          message: `${user.username} is back!`,
          token,
        })
      }

      next({ status: 401, message: 'Invalid credentials' })
    })
    .catch(next)
})

module.exports = router
