import { IUserMongoDb, IUserRepository } from "../repositories/UserRepository"
import { isCheckClientBadRequestOk } from "../middlewares/errorCheck"
import { NextFunction, Request, Response } from "express"
import createError from 'http-errors'
import jwt from 'jsonwebtoken'
import { IUser } from "../models/User"


export interface IUserService {
  loginUser(req: Request, res: Response, next: NextFunction): Promise<string | null>,
  registerUser(req: Request, res: Response, next: NextFunction): void
}

export class UserService implements IUserService {
  #userRepository

  constructor(UserRepository: IUserRepository) {
    this.#userRepository = UserRepository
  }

  async registerUser(req: Request, res: Response, next: NextFunction) {
    try {
      isCheckClientBadRequestOk(req, res, next)
    
      await this.#userRepository.registerUser(req, res, next)
    } catch (error) {
      this.#handleValidationErrorRegister(error)
    }
  }

  async loginUser(req: Request, res: Response, next: NextFunction): Promise<string | null> {
    if(process.env.PRIVATE_KEY !== undefined) {
      const token = Buffer.from(process.env.PRIVATE_KEY, 'base64')

      const user: IUser | null = await this.#userRepository.loginUser(req, res, next)

      if(user) {
        const payload = {
          username: user.username,
          email: user.email,
          id: user._id
        }
        
        const accessToken = jwt.sign(payload, token, {
          algorithm: 'RS256',
          expiresIn: process.env.ACCESS_TOKEN_LIFE
        })
  
        return accessToken
      }
    }

    return null
  }

  #handleValidationErrorRegister(error: any) {
    if(error.code === 11000) {
      throw createError(400, 'This username or email is already in use. Please choose a different username or use a different email address.')
    } else if(error.errors.password.path === 'password') {
      throw createError(400, error.errors.password.message)
    } else {
      throw error
    }
  }
}