import { IAuthMongoDb, IAuthRepository } from "../repositories/AuthRepository"
import { isCheckClientBadRequestOk } from "../middlewares/errorCheck"
import { NextFunction, Request, Response } from "express"
import createError from 'http-errors'
import jwt, { JwtPayload, Secret } from 'jsonwebtoken'
import { IUser } from "../models/User"
import { ObjectId } from "mongoose"
import { RefreshToken } from "../models/refreshToken"


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

interface IUserPayload extends JwtPayload {
  username: string,
  email: string,
  _id: string
}

interface ITokens {
  accessToken: string,
  refreshToken: string
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

          const tokens = {
            accessToken: accessToken,
            refreshToken: tokenForRefresh
          }
  
          // this.db.push(tokenForRefresh)
          // console.log(this.db)
          this.#authRepository.addRefreshTokenToDb(tokenForRefresh)
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
  console.log('REFRESHTOKEN:')
  console.log(refreshToken)

  if (refreshToken == null) {
    console.log('refresh token isnt null')
    throw createError(401, 'Unauthorized: Missing refreshToken')
  }

  // Implement database here..

  console.log('---------------************------------------')

  if(!await this.#authRepository.isRefreshTokenIncludesInDataBase(refreshToken)) {
    throw createError(403, 'Forbidden: Invalid refreshToken')
  }

  /* if (!this.db.includes(refreshToken)) {
    console.log('refreshtoken isnt in this db.')
    throw createError(403, 'Forbidden: Invalid refreshToken');
  } */

  if (process.env.REFRESH_TOKEN_SECRET) {
    try {
      // Vänta på resultatet av verifieringen innan du går vidare
      const decoded = jwt.verify(
        refreshToken,
        process.env.REFRESH_TOKEN_SECRET
      ) as IPayloadUser

      if (process.env.PRIVATE_KEY) {
        const token = Buffer.from(process.env.PRIVATE_KEY, 'base64')
        accessToken = this.#generateAccessToken(decoded, token)
      }
    } catch (err) {
      throw createError(403, 'Forbidden: Invalid refreshToken')
    }
  }

  return accessToken
}

  #generateAccessToken(user: IPayloadUser, token: Secret) {
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