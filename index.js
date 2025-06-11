import express from 'express'
import jwt from 'jsonwebtoken'
import cookieParser from 'cookie-parser'
import { PORT, SECRET_JWT_KEY } from './config.js'
import rateLimit from 'express-rate-limit'
import { UserRepository } from './user-repository.js'
import { sendPasswordResetEmail } from './email-services.js'

const app = express()

const passwordResetLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 3,
  message: 'Demasiados intentos, por favor intenta más tarde'
})

app.set('view engine', 'ejs')

app.use(express.json())
app.use(cookieParser())

app.use((req, res, next) => {
  const token = req.cookies.access_token
  req.session = { user: null }

  try {
    const data = jwt.verify(token, SECRET_JWT_KEY)
    req.session.user = data
  } catch {}

  next()
})

app.get('/', (req, res) => {
  const { user } = req.session
  res.render('index', user)
})

app.post('/login', async (req, res) => {
  const { username, password } = req.body

  try {
    const user = await UserRepository.login({ username, password })
    const token = jwt.sign(
      { user: user._id, username: user.username, role: user.role || 'user' },
      SECRET_JWT_KEY,
      {
        expiresIn: '1h'
      })
    res
      .cookie('access_token', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 1000 * 60 * 60
      })
      .send({ user, token })
  } catch (error) {
    res.status(401).send(error.message)
  }
})

app.post('/register', async (req, res) => {
  const { email, username, password, role = 'user' } = req.body

  // Validar que el rol sea válido
  const validRoles = ['user', 'admin']
  if (!validRoles.includes(role)) {
    return res.status(400).send('Rol no válido')
  }

  // En producción, podrías restringir quién puede crear usuarios admin
  if (role === 'admin' && process.env.NODE_ENV === 'production') {
    const currentUser = req.session.user
    if (!currentUser || currentUser.role !== 'admin') {
      return res.status(403).send('No puedes crear un usuario admin')
    }
  }

  try {
    const id = await UserRepository.create({ email, username, password, role })
    res.send({ id, message: 'User registered successfully' })
  } catch (error) {
    res.status(400).send(error.message)
  }
})

app.post('/logout', (req, res) => {
  res
    .clearCookie('access_token')
    .json({ message: 'Logged out successfully' })
})

app.get('/protected', (req, res) => {
  const { user } = req.session
  if (!user) {
    return res.status(401).send('Acess not Authorized')
  }
  res.render('protected', user)
})

app.get('/admin', authorizeRole('admin'), (req, res) => {
  const { user } = req.session
  res.render('admin', { user, message: 'Welcome to the admin page!' })
})

app.get('/user', (req, res) => {
  const { user } = req.session
  if (!user) {
    return res.redirect('/')
  }
  res.render('user', { user })
})

app.get('/forgot-password', (req, res) => {
  res.render('forgot-password')
})

app.get('/reset-password', (req, res) => {
  res.render('reset-password')
})

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`)
})

app.post('users/:id/role', authorizeRole('admin'), async (req, res) => {
  try {
    const { id } = req.params
    const { role } = req.body

    const updateUser = await UserRepository.updateRole(id, role)
    res.json(updateUser)
  } catch (error) {
    res.status(400).send(error.message)
  }
})

app.post('/forgot-password', passwordResetLimiter, async (req, res) => {
  const { email } = req.body

  if (!email || typeof email !== 'string' || !email.includes('@')) {
    return res.status(400).json({
      success: false,
      error: 'Formato de email inválido'
    })
  }

  try {
    const normalizedEmail = email.trim().toLowerCase()
    const user = await UserRepository.findByEmail(normalizedEmail)

    const responseMessage = 'Si este correo está registrado, recibirás un enlace para restablecer tu contraseña'

    if (!user) {
      console.log('Usuario encontrado. Generando token...')

      const resetToken = jwt.sign(
        {
          userId: user._id,
          action: 'password-reset',
          email: user.email,
          iat: Math.floor(Date.now() / 1000),
          exp: Math.floor(Date.now() / 1000) + 3600 // 1 hora
        },
        SECRET_JWT_KEY,
        { algorithm: 'HS256' }
      )

      await UserRepository.saveResetToken(user.email, resetToken)

      await sendPasswordResetEmail({
        email: user.email,
        username: user.username,
        resetLink: `http://localhost:3000/reset-password?token=${resetToken}`
      })

      console.log(`Token de reset generado para ${user.email}`)
      console.log('Token generado:', resetToken)
      console.log('Token decodificado:', jwt.decode(resetToken))
    }
    return res.json({
      success: true,
      message: responseMessage
    })
  } catch (error) {
    console.error('Error en /forgot-password:', error)
    return res.status(500).json({
      success: false,
      error: 'Error al procesar la solicitud',
      ...(process.env.NODE_ENV === 'development' && {
        details: error.message
      })
    })
  }
})

app.post('/reset-password', async (req, res) => {
  const { token, newPassword } = req.body
  console.log('Token recibido:', token)

  if (!token || !newPassword) {
    return res.status(400).json({ error: 'Token y nueva contraseña son requeridos' })
  }

  try {
    const decoded = jwt.verify(token, SECRET_JWT_KEY)
    console.log('Token decodificado:', decoded)

    if (decoded.action !== 'password-reset') {
      return res.status(400).json({ error: 'Token inválido' })
    }

    const user = await UserRepository.findByResetToken(token)
    if (!user) {
      return res.status(400).json({ error: 'Token inválido o expirado' })
    }

    await UserRepository.updatePassword(decoded.userId, newPassword)

    await UserRepository.clearResetToken(decoded.userId)

    return res.json({ success: true, message: 'Contraseña actualizada exitosamente' })
  } catch (error) {
    console.error('Error al verificar token:', error.message)
    console.error('Error al resetear contraseña:', error)

    if (error instanceof jwt.JsonWebTokenError) {
      return res.status(400).json({ error: 'Token inválido o expirado' })
    }

    return res.status(500).json({ error: 'Error al procesar la solicitud' })
  }
})

app.get('/users', authorizeRole('admin'), async (req, res) => {
  try {
    const users = await UserRepository.list()
    res.json(users)
  } catch (error) {
    res.status(500).send(error.message)
  }
})

function authorizeRole (requiredRole) {
  return (req, res, next) => {
    const user = req.session.user

    if (!user) {
      return res.status(401).send('No autenticado')
    }

    // Si el requiredRole es un array, verificamos si el usuario tiene alguno de esos roles
    const requiredRoles = Array.isArray(requiredRole) ? requiredRole : [requiredRole]

    if (!requiredRoles.includes(user.role)) {
      return res.status(403).send('Acceso denegado: Rol insuficiente')
    }

    next()
  }
}

// Uso con múltiples roles:
app.get('/manager', authorizeRole(['admin', 'manager']), (req, res) => {
  res.render('manager', { user: req.session.user })
})
