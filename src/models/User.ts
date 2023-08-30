import mongoose, { Model } from 'mongoose'
import bcrypt from 'bcrypt'

interface IUser {
  username: string,
  email: string,
  password: string
}

interface IUserModel extends Model<IUser> {
  authenticate(username: string, password: string): Promise<IUser | null>
}

const userSchema = new mongoose.Schema<IUser>({
  username: { 
    type: String, 
    required: true 
  },
  email: { 
    type: String, 
    required: true 
  },
  password: { 
    type: String, 
    required: true 
  }
}, {
  timestamps: true
}  
)

userSchema.pre('save', async function () {
  this.password = await bcrypt.hash(this.password, 10)
})

/**
 * Checks if the password matches and if the user exists.
 *
 * @param {string} username - Username for login.
 * @param {string} password - Password for login.
 */
userSchema.statics.authenticate = async function (username, password) {
  console.log('We are inside of this')
  const user = await this.findOne({ username })

  // If no user found or password is wrong, throw an error.
  if (!(await bcrypt.compare(password, user?.password))) {
    throw new Error('Invalid credentials.')
  }

  // User found and password correct, return the user.
  return user
}

export const User: IUserModel = mongoose.model<IUser, IUserModel>('User', userSchema)