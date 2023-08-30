import { IUserRepository } from "../repositories/UserRepository"
import { isCheckClientBadRequestOk } from "../middlewares/errorCheck"
import { NextFunction, Request, Response } from "express"
import createError from 'http-errors'
import jwt from 'jsonwebtoken'


export interface IUserService {
  loginUser(req: Request, res: Response, next: NextFunction): void,
  registerUser(req: Request, res: Response, next: NextFunction): void,
  deleteUser(): void,
  updateUser(): void
}

/* export interface ILoginDetails {
  name: string,
  password: string,
  email: string
} */

export class UserService implements IUserService {
  constructor(private UserRepository: IUserRepository) {
    this.UserRepository = UserRepository
  }

  async registerUser(req: Request, res: Response, next: NextFunction) {
    isCheckClientBadRequestOk(req, res, next)
  
    await this.UserRepository.registerUser(req, res, next)
  }

  async loginUser(req: Request, res: Response, next: NextFunction) {
    console.log('login a user')
    let token
    if(process.env.PRIVATE_KEY !== undefined) {
      token = Buffer.from(process.env.PRIVATE_KEY, 'base64')

      console.log(token)
      
      const user: any = await this.UserRepository.loginUser(req, res, next) // change this any to a correct one..
      console.log(user)
      console.log(token)
      console.log(user.username)
      const payload = {
        username: user.username,
        email: user.email,
        id: user._id
      }
      
      const accessToken = jwt.sign(payload, token, {
        algorithm: 'RS256',
        expiresIn: process.env.ACCESS_TOKEN_LIFE
      })
      console.log(accessToken)

      return accessToken
    }

  }

  updateUser() {
    console.log('update a user')
  }

  deleteUser() {
    console.log('delete user')
  }
}