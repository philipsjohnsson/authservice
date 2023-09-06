import mongoose from "mongoose"
import AES from 'crypto-js/aes'
import CipherParams from 'crypto-js'
import bcrypt from 'bcrypt'

const refreshTokenSchema = new mongoose.Schema({
  token: {
    type: String,
    required: true,
    unique: true,
    active: true
  }
}, {
  timestamps: true
})

refreshTokenSchema.pre('save', async function() {
  // this.token = await bcrypt.hash(this.token, 10)
  // this.token = await AES.encrypt(this.token, 'process.env.ENCRYPTION_KEY')
})

refreshTokenSchema.statics.authenticate = async function (token) {
/* 
  // If no user found or password is wrong, throw an error.
  if (!(await bcrypt.compare(password, user?.password))) {
    throw createError(400)
  }

  // User found and password correct, return the user.
  return user */
}

export const RefreshToken = mongoose.model('RefreshToken', refreshTokenSchema)
