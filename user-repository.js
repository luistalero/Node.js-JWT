import crypto from 'node:crypto'

import DBLocal from 'db-local'
import bcrypt from 'bcrypt'

import { SALT_ROUNDS } from './config.js'
const { Schema } = new DBLocal({ path: './db' })

const User = Schema('User', {
  _id: { type: String, required: true },
  username: { type: String, required: true },
  password: { type: String, required: true },
  role: { type: String, require: true }
})

export class UserRepository {
  static async create ({ username, password, role = 'user' }) {
    Validations.username(username)
    Validations.password(password)

    const user = User.findOne({ username })
    if (user) {
      throw new Error('User already exists')
    }

    const id = crypto.randomUUID()
    const hasedPassword = await bcrypt.hash(password, SALT_ROUNDS)

    User.create({
      _id: id,
      username,
      password: hasedPassword,
      role
    }).save()

    return id
  }

  static async login ({ username, password }) {
    Validations.username(username)
    Validations.password(password)

    const user = User.findOne({ username })
    if (!user) throw new Error('User not found')

    const isValid = await bcrypt.compare(password, user.password)
    if (!isValid) throw new Error('Invalid password')

    const { password: _, ...publicUser } = user

    return publicUser
  }

  static async getById (id) {
    const user = User.findOne({ _id: id })
    if (!user) throw new Error('User not found')

    const { password: _, ...publicUser } = user
    return publicUser
  }

  static async updateRole (userId, newRole) {
    const user = User.findOne({ _id: userId })
    if (!user) throw new Error('User not found')

    user.role = newRole
    user.save()

    return user
  }
}

class Validations {
  static username (username) {
    if (typeof username !== 'string' || username.length < 3) {
      throw new Error('Username must be a string with at least 3 characters')
    }
  }

  static password (password) {
    if (typeof password !== 'string' || password.length < 6) {
      throw new Error('Password must be a string with at least 6 characters')
    }
  }
}
