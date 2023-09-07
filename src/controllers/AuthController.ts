import { DELETE, GET, POST, route } from "awilix-express"
import { IAuthService } from "../services/AuthService"
import { NextFunction, Request, Response } from "express"
import jwt from 'jsonwebtoken'
import jwt_decode, { JwtPayload } from 'jwt-decode'

interface IAuthController {
  registerUser(req: Request, res: Response, next: NextFunction): void,
  loginUser(req: Request, res: Response, next: NextFunction): void,
  logoutUser(req: Request, res: Response, next: NextFunction): void,
  refreshToken(req: Request, res: Response, next: NextFunction): void
}

interface IPayloadUser {
  username: string,
  email: string,
  _id: string,
  iat: number,
  exp: number
}

interface MyToken {
  username: string,
  email: string,
  _id: string,
  iat: number,
  exp: number
}

@route('/auth')
export class AuthController implements IAuthController {
  #authService

  constructor(AuthService: IAuthService) {
    this.#authService = AuthService
  }

  @route('/register')
  @POST()
  async registerUser(req: Request, res: Response, next: NextFunction) {
    try {
      await this.#authService.registerUser(req, res, next)

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
      const accessToken = await this.#authService.loginUser(req, res, next)
  
      res
        .status(200)
        .json({tokens: accessToken})
    } catch (error) {
      console.log(error)
      next(error)
    }
  }

  @route('/logout')
  @DELETE()
  async logoutUser(req: Request, res: Response, next: NextFunction) {
    try {
      await this.#authService.logoutUser(req, res, next)

      res
        .status(204)
    } catch (error) {
      next(error)
    }
  }

  @route('/refresh/token')
  @POST()
  async refreshToken(req: Request, res: Response, next: NextFunction) {
    try {
      const accessToken = await this.#authService.refreshToken(req, res, next)

      res
        .status(201)
        .json({accessToken: accessToken})

    } catch (error) {
      next(error)
    }
  }
}