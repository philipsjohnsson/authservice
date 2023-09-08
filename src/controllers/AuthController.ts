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
      const accessTokenAndRefreshToken = await this.#authService.generateRefreshAndAccessToken(req, res, next)
  
      res
        .status(200)
        .json({tokens: accessTokenAndRefreshToken})
    } catch (error) {
      next(error)
    }
  }

  @route('/logout')
  @DELETE()
  async logoutUser(req: Request, res: Response, next: NextFunction) {
    try {
      await this.#authService.removeRefreshTokenBasedOnUser(req, res, next)

      res
        .status(204)
        .json({})
    } catch (error) {
      next(error)
    }
  }

  // Just for simple testing, will be removed..
  @route('/test/token')
  @POST()
  async testToken(req: Request, res: Response, next: NextFunction) {
    try {
      if(process.env.PUBLIC_KEY) {
        const publicKey = Buffer.from(process.env.PUBLIC_KEY, 'base64')
        let [authenticationScheme, token]: any = req.headers.authorization?.split(' ')

        const decodedJwt = jwt_decode<JwtPayload>(token)

        if(decodedJwt.exp && Date.now() >= decodedJwt.exp * 1000 ) {
          const data = {
            refreshToken: req.body.refreshToken,
            username: "Philip"
          }
          const response = await fetch('http://localhost:4050/auth/refresh/token', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(data)
          })

          const responseJson = await response.json()
          token = responseJson.accessToken
        }

        const test = jwt.verify(token, publicKey)
        console.log(test)
      }
    } catch (error) {
      next(error)
    }
  }

  @route('/refresh/token')
  @POST()
  async refreshToken(req: Request, res: Response, next: NextFunction) {
    try {
      const accessToken = await this.#authService.genereateNewRefreshAndAccessToken(req, res, next)

      res
        .status(201)
        .json({accessToken: accessToken})

    } catch (error) {
      next(error)
    }
  }
}