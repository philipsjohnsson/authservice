import { GET, POST, route } from "awilix-express"
import { IUserService } from "../services/UserService"
import { User } from "../models/User"
import { NextFunction, Request, Response } from "express"
import createError, { HttpError } from 'http-errors';

interface CustomError extends Error {
  status?: number
}


@route('/user')
export class UserController {
  #userService

  constructor(UserService: IUserService) {
    this.#userService = UserService
  }

  @route('/register')
  @POST()
  async registerUser(req: Request, res: Response, next: NextFunction) {
    try {
      console.log('register')
      await this.#userService.registerUser(req, res, next)

      res
        .status(201)
        .json('Created a user')

    } catch (error: any) {
      next(error)
    }
  }

  @route('/login')
  @POST()
  async loginUser(req: Request, res: Response, next: NextFunction) {
    try {
      const accessToken = await this.#userService.loginUser(req, res, next)
  
      res
        .status(200)
        .json({access_token: accessToken})
    } catch (error) {
      next(error)
    }
  }
}