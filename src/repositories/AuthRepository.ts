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
  addRefreshTokenToDb(tokenForRefresh: string): void,
  isRefreshTokenIncludesInDataBase(refreshToken: string): Promise<boolean> 
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

  async addRefreshTokenToDb(tokenForRefresh: string) {
    if(process.env.ENCRYPTION_KEY) {
      const encryptedRefreshToken = await AES.encrypt(tokenForRefresh, process.env.ENCRYPTION_KEY)
      
      const newRefreshToken = new RefreshToken({
        token: tokenForRefresh
      })
  
      await newRefreshToken.save()
    } else {
      throw createError(500)
    }
  }

  async isRefreshTokenIncludesInDataBase(refreshToken: string): Promise<boolean> {
    console.log('check refresh token')
    if(process.env.ENCRYPTION_KEY) {
      // const encryptedRefreshToken = await AES.encrypt(refreshToken, process.env.ENCRYPTION_KEY)
      // const encryptedRefreshToken2 = await AES.encrypt(refreshToken, process.env.ENCRYPTION_KEY)
      // console.log(encryptedRefreshToken.toString())
      const token = await RefreshToken.findOne({ token: refreshToken })
      // const test = await RefreshToken.findOne({ token: 'nothing' })
      console.log(token)
      if(token === null) {
        return false
      } else {
        return true
      }
    } else {
      throw createError(500)
    }
  }
}