import mongoose, { Model, ObjectId } from 'mongoose'
import bcrypt from 'bcrypt'
import createError from 'http-errors'

export interface IUser {
  _id: ObjectId,
  username: string,
  email: string,
  password: string,
  createdAt: Date,
  updatedAt: Date,
  __v: number
}

interface IUserModel extends Model<IUser> {
  authenticate(username: string, password: string): Promise<IUser | null>
}

const userSchema = new mongoose.Schema<IUser>({
  username: { 
    type: String, 
    required: true,
    unique: true,
    match: [/^[A-Za-z][A-Za-z0-9_-]{2,255}$/, 'Please provide a valid username.']
  },
  email: { 
    type: String, 
    required: true,
    unique: true
  },
  password: { 
    type: String, 
    required: true,
    minlength: [10, 'The password must be of minimum length 10 characters.'],
    maxlength: [200, 'The password must be shorter than 200.']
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
userSchema.statics.authenticate = async function (username, password): Promise<IUser> {
  const user = await this.findOne({ username })

  // If no user found or password is wrong, throw an error.
  if (!user || !(await bcrypt.compare(password, user?.password))) {
    throw createError(400)
  }

  // User found and password correct, return the user.
  return user
}

export const User: IUserModel = mongoose.model<IUser, IUserModel>('User', userSchema)
