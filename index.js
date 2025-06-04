import express from 'express'
import jwt from 'jsonwebtoken'
import cookieParser from 'cookie-parser'
import { PORT, SECRET_JWT_KEY } from './config.js'
import { UserRepository } from './user-repository.js'

const app = express()

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
  const { username, password, role = 'user' } = req.body

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
    const id = await UserRepository.create({ username, password, role })
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
