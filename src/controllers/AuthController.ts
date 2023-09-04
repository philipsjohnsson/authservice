import { GET, POST, route } from "awilix-express"
import { IAuthService } from "../services/AuthService"
import { NextFunction, Request, Response } from "express"
import jwt from 'jsonwebtoken'

interface IAuthController {
  registerUser(req: Request, res: Response, next: NextFunction): void,
  loginUser(req: Request, res: Response, next: NextFunction): void,
  refreshToken(req: Request, res: Response, next: NextFunction): void
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

  @route('/test/token')
  @POST()
  async testToken(req: Request, res: Response, next: NextFunction) {
    try {
      console.log('TEST TOKEN')
      if(process.env.PUBLIC_KEY) {
        const publicKey = Buffer.from(process.env.PUBLIC_KEY, 'base64')
        const [authenticationScheme, token]: any = req.headers.authorization?.split(' ')
        console.log(authenticationScheme)
        console.log(token)
        console.log(publicKey)
        console.log('ÅÅÅÅÅÅÅ')
        console.log('___--__--__')
        const test = jwt.verify(token, publicKey)
        console.log('-----')
        console.log(test)
      }
    } catch (error) {
      console.log(error)
    }
  }

  @route('/refresh/token')
  @GET()
  async refreshToken(req: Request, res: Response, next: NextFunction) {
    try {
      console.log(req.body)
      const refreshToken = req.body.token
      const accessToken = await this.#authService.refreshToken(req, res, next)
      console.log(accessToken)
      console.log('RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR')
      // const refreshToken
      res
        .status(201)
        .json({accessToken: accessToken})

    } catch (error) {
      console.log('ERROR HANDLING')
      console.log(error)
      next(error)
    }
  }
}