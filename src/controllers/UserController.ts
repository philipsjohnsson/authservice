import { POST, route } from "awilix-express"
import { IUserService } from "../services/UserService"
import { NextFunction, Request, Response } from "express"

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
      await this.#userService.registerUser(req, res, next)

      res
        .status(201)
        .json('Created a user')

    } catch (error) {
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