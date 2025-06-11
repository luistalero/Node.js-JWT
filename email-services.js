import nodemailer from 'nodemailer'
import jwt from 'jsonwebtoken'
import { config } from 'dotenv'
config()

const transporter = nodemailer.createTransport({
  service: process.env.EMAIL_SERVICE,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD
  }
})

export function createPasswordResetToken (user) {
  if (!user?._id) {
    throw new Error('Usuario no tiene _id válido')
  }
  return jwt.sign(
    {
      userId: user._id,
      role: user.role,
      action: 'password-reset'
    },
    process.env.SECRET_JWT_KEY,
    { expiresIn: '1h' }
  )
}

export async function sendPasswordResetEmail (userData) {
  try {
    const mailOptions = {
      from: process.env.EMAIL_FROM,
      to: userData.email,
      subject: 'Recuperación de contraseña',
      html: `
        <div style="font-family: Arial, sans-serif;">
          <h2>Recuperación de contraseña</h2>
          <p>Hola ${userData.username},</p>
          <p>Haz clic en el siguiente enlace para restablecer tu contraseña:</p>
          <a href="${userData.resetLink}">Restablecer contraseña</a>
          <p>Si no solicitaste este cambio, ignora este correo.</p>
        </div>
      `
    }

    await transporter.sendMail(mailOptions)
    return true
  } catch (error) {
    console.error('Error al enviar email:', error)
    throw new Error('Error al enviar el correo de recuperación')
  }
}
