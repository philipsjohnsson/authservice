import { GET, POST, route } from "awilix-express"
import { IUserService } from "../services/UserService"
import { User } from "../models/User"
import { NextFunction, Request, Response } from "express"

@route('/user')
export class UserController {
  constructor(private UserService: IUserService) {
    this.UserService = UserService
  }

  @route('/register')
  @POST()
  async registerUser(req: Request, res: Response, next: NextFunction) {
    try {
      await this.UserService.registerUser(req, res, next)

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
    const accessToken = await this.UserService.loginUser(req, res, next)

    res
      .status(201)
      .json({access_token: accessToken})
  }

  /* testLogin = async () => {
    console.log('TEST LOGIN')
    this.AuthService.registerUser()
    const user = new User({
      name: 'Bill',
      email: 'bill@gmail.com',
      password: "test"
    })

    await user.save()
  } */
}