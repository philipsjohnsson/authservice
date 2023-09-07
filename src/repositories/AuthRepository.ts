import { NextFunction, Request, Response } from "express"
import { IUser, User } from "../models/User"
import { ObjectId } from "mongoose"
import createError from 'http-errors'
import { RefreshToken } from "../models/refreshToken"
import { AES } from "crypto-js"

export interface IAuthMongoDb {
  _id: ObjectId,
  username: string,
  email: string,
  password: string,
  createdAt: Date,
  updatedAt: Date,
  __v: number
}


export interface IAuthRepository {
  registerUser(req: Request, res: Response, next: NextFunction): void,
  loginUser(req: Request, res: Response, next: NextFunction): Promise<IUser | null>,
  deleteRefreshToken(user: string): void,
  addRefreshTokenToDb(user: string, tokenForRefresh: string): void,
  getRefreshTokenBasedOnUserFromDb(user: string): Promise<string | null>
}

export class AuthRepository implements IAuthRepository {

  async registerUser(req: Request, res: Response, next: NextFunction) {
      const newUser = new User({
        username: req.body.username,
        email: req.body.email,
        password: req.body.password
      })
  
      await newUser.save({ validateBeforeSave: true })
  }

  async loginUser(req: Request, res: Response, next: NextFunction): Promise<IUser | null> {
    return await User.authenticate(req.body.username, req.body.password)
  }

  async deleteRefreshToken(user: string) {
    console.log(user)

    const deleted = await RefreshToken.deleteMany({ user: user })
    console.log(deleted)
  }

  async addRefreshTokenToDb(user: string, tokenForRefresh: string) {
    if(process.env.ENCRYPTION_KEY) {

      this.deleteRefreshToken(user)
      
      const newRefreshToken = new RefreshToken({
        token: tokenForRefresh,
        user: user
      })
  
      await newRefreshToken.save()
    } else {
      throw createError(500)
    }
  }

  async getRefreshTokenBasedOnUserFromDb(user: string) {
    console.log('^ÅEKMKEKRMEKR')
    console.log(user)
    const refreshTokenBasedOnUser = await RefreshToken.findOne({ user: user })
    console.log('TEST TEST')
    console.log(refreshTokenBasedOnUser)
    if(refreshTokenBasedOnUser !== null) {
      console.log('^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^')
      console.log(refreshTokenBasedOnUser)
      return refreshTokenBasedOnUser.token
    } else {
      return null
    }
  }
}