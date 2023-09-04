import { IAuthMongoDb, IAuthRepository } from "../repositories/AuthRepository"
import { isCheckClientBadRequestOk } from "../middlewares/errorCheck"
import { NextFunction, Request, Response } from "express"
import createError from 'http-errors'
import jwt, { JwtPayload, VerifyOptions, VerifyErrors, VerifyCallback } from 'jsonwebtoken'
import { IUser } from "../models/User"
import crypto from 'crypto'
import { ObjectId } from "mongoose"


export interface IAuthService {
  refreshToken(req: Request, res: Response, next: NextFunction): Promise<string | null>,
  loginUser(req: Request, res: Response, next: NextFunction): Promise<object | null>,
  registerUser(req: Request, res: Response, next: NextFunction): void
}

interface IPayloadUser {
  username: string,
  email: string,
  _id: string,
  iat: number,
  exp: number
}

/* interface IUserJwtPayload extends JwtPayload {
  username: string,
  email: string,
  _id: string,
  iat: number,
  exp: number
} */

interface IUserTest {
  username: string;
  email: string;
  _id: string;
}

interface IUserJwtPayload extends JwtPayload {
  username: string,
  email: string,
  _id: string
}

interface ITokens {
  accessToken: string,
  refreshToken: string
}

type IVerifyCallback = {
  err: VerifyErrors | null,
  user: any
}

export class AuthService implements IAuthService {
  #authRepository
  db: any[]

  constructor(AuthRepository: IAuthRepository) {
    this.#authRepository = AuthRepository
    this.db = []
  }

  async registerUser(req: Request, res: Response, next: NextFunction) {
    try {
      isCheckClientBadRequestOk(req, res, next)
    
      await this.#authRepository.registerUser(req, res, next)
    } catch (error) {
      this.#handleValidationErrorRegister(error)
    }
  }

  async loginUser(req: Request, res: Response, next: NextFunction): Promise<ITokens | null> {
    if(process.env.PRIVATE_KEY !== undefined) {
      const token = Buffer.from(process.env.PRIVATE_KEY, 'base64')

      const refreshToken = process.env.REFRESH_TOKEN_SECRET
      if(refreshToken !== undefined) {

      const user: IUser | null = await this.#authRepository.loginUser(req, res, next)

      if(user) {
        const payload = {
          username: user.username,
          email: user.email,
          id: user._id
        }
        
        const accessToken = jwt.sign(payload, token, {
          algorithm: 'RS256',
          expiresIn: '30s'
        })

          const tokenForRefresh = jwt.sign(payload, refreshToken, {
            expiresIn: '1d'
          })
          console.log('test')
          console.log(accessToken)
          console.log('------------------------------')
          console.log(tokenForRefresh)
          this.db.push(tokenForRefresh)

          const tokens = {
            accessToken: accessToken,
            refreshToken: tokenForRefresh
          }
  
          this.db.push(tokenForRefresh)
          return tokens
        }

        return null
      }
    }

    return null
  }

  async refreshToken(req: Request, res: Response, next: NextFunction): Promise<string | null> {
    const refreshToken = req.body.refreshToken
    let accessToken = null

    if(refreshToken == null) {
      throw createError(401)
    }
    if(!refreshToken.includes(refreshToken)) {
      throw createError(403)
    }
    
    if(process.env.REFRESH_TOKEN_SECRET) {
      jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, async (err: VerifyErrors | null, user: any) => {
        if(err) {
          throw createError(403)
        }
        if(process.env.PRIVATE_KEY) {
          const token = Buffer.from(process.env.PRIVATE_KEY, 'base64')
          accessToken = this.#generateAccessToken(user, token)
        }
      })
    }

    return accessToken
  }

  #generateAccessToken(user: IPayloadUser, token: any) {
    console.log(user)
    const payload = {
      username: user.username,
      email: user.email,
      id: user._id
    }
    const accessToken = jwt.sign(payload, token, {
      algorithm: 'RS256',
      expiresIn: '30s'
    })

    return accessToken
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