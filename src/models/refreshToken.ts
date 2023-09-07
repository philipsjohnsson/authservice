import mongoose from "mongoose"
import AES from 'crypto-js/aes'
import CipherParams from 'crypto-js'
import bcrypt from 'bcrypt'

export interface IRefreshToken {
  token: string,
  user: string
}

const refreshTokenSchema = new mongoose.Schema({
  token: {
    type: String,
    required: true,
    unique: true
  },
  user: {
    type: String,
    required: true,
    unique: true
  }
}, {
  timestamps: true
})

refreshTokenSchema.pre('save', async function () {
  if(process.env.ENCRYPTION_KEY) {
    this.token = await AES.encrypt(this.token, process.env.ENCRYPTION_KEY).toString()
  }
})

export const RefreshToken = mongoose.model<IRefreshToken>('RefreshToken', refreshTokenSchema)
