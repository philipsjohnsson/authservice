import { NextFunction, Request, Response } from "express"
import { IUser, User } from "../models/User"
import { ObjectId } from "mongoose"
import createError from 'http-errors'

export interface IUserMongoDb {
  _id: ObjectId,
  username: string,
  email: string,
  password: string,
  createdAt: Date,
  updatedAt: Date,
  __v: number
}


export interface IUserRepository {
  registerUser(req: Request, res: Response, next: NextFunction): void
  loginUser(req: Request, res: Response, next: NextFunction): Promise<IUser | null>
}

export class UserRepository implements IUserRepository {

  async registerUser(req: Request, res: Response, next: NextFunction) {
    try {
      const newUser = new User({
        username: req.body.username,
        email: req.body.email,
        password: req.body.password
      })
  
      await newUser.save({ validateBeforeSave: true })
    } catch (error) {
      throw createError(500)
    }
  }

  async loginUser(req: Request, res: Response, next: NextFunction): Promise<IUser | null> {
    try {
      return await User.authenticate(req.body.username, req.body.password)
    } catch (error) {
      throw createError(500)
    }
  }
}