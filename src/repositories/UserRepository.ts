import { NextFunction, Request, Response } from "express"
import { User } from "../models/User"

interface IUserMongoDb {
  username: string,
  email: string,
  password: string
}


export interface IUserRepository {
  registerUser(req: Request, res: Response, next: NextFunction): void
  loginUser(req: Request, res: Response, next: NextFunction): void
}

export class UserRepository implements IUserRepository {
  constructor() {
    
  }

  async registerUser(req: Request, res: Response, next: NextFunction) {
    const newUser = new User({
      username: req.body.username,
      email: req.body.email,
      password: req.body.password
    })

    await newUser.save()
  }

  async loginUser(req: Request, res: Response, next: NextFunction): Promise<IUserMongoDb | null> {
    return await User.authenticate(req.body.username, req.body.password)
  }
}