import crypto from 'node:crypto'

import DBLocal from 'db-local'
import bcrypt from 'bcrypt'

import { SALT_ROUNDS } from './config.js'
const { Schema } = new DBLocal({ path: './db' })

export const User = Schema('User', {
  _id: { type: String, required: true },
  email: { type: String, required: true },
  username: { type: String, required: true },
  password: { type: String, required: true },
  role: { type: String, require: true },
  resetToken: { type: String }
})

export class UserRepository {
  static async create ({ email, username, password, role = 'user' }) {
    const validRoles = ['user', 'admin']
    if (!validRoles.includes(role)) {
      throw new Error(`Invalid role. Valid roles are: ${validRoles.join(', ')}`)
    }
    Validations.username(username)
    Validations.password(password)

    const user = User.findOne({ username })
    if (user) {
      throw new Error('User already exists')
    }
    const correo = User.findOne({ email })
    if (correo) {
      throw new Error('User already exists')
    }

    const id = crypto.randomUUID()
    const hasedPassword = await bcrypt.hash(password, SALT_ROUNDS)

    User.create({
      _id: id,
      email,
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

  static async findByEmail (email) {
    if (typeof email !== 'string' || !email.includes('@')) {
      throw new Error('Invalid email format')
    }

    const normalizedEmail = email.trim().toLocaleLowerCase()
    const user = User.findOne({ email: normalizedEmail })
    if (!user) return null

    return user
  }

  static async saveResetToken (email, token) {
    const user = await User.findOne({ email })

    if (!user) {
      throw new Error('There is no user with this email')
    }

    if (typeof token !== 'string' || !token.startsWith('eyJ')) {
      throw new Error('Token JWT inválido')
    }

    user.resetToken = token
    await user.save()

    return user
  }

  static async findByResetToken (token) {
    if (typeof token !== 'string' || !token.startsWith('eyJ')) {
      throw new Error('Invalid token format')
    }

    const user = User.findOne({ resetToken: token })
    if (!user) return null

    return user
  }

  static async updatePassword (userId, newPassword) {
    Validations.password(newPassword)

    const user = User.findOne({ _id: userId })
    if (!user) {
      throw new Error('User not found')
    }

    const hashedPassword = await bcrypt.hash(newPassword, SALT_ROUNDS)
    user.password = hashedPassword
    user.save()

    return user
  }

  static async clearResetToken (userId) {
    const user = await User.findOne({ _id: userId })

    if (!user) {
      throw new Error('Usuario no encontrado')
    }

    user.resetToken = null
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
