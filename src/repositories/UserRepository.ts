import { NextFunction, Request, Response } from "express"
import { IUser, User } from "../models/User"
import { ObjectId } from "mongoose"

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
    const newUser = new User({
      username: req.body.username,
      email: req.body.email,
      password: req.body.password
    })
    console.log(newUser)

    const response = await newUser.save({ validateBeforeSave: true })
    console.log(response)
  }

  async loginUser(req: Request, res: Response, next: NextFunction): Promise<IUser | null> {
      return await User.authenticate(req.body.username, req.body.password)
  }
}