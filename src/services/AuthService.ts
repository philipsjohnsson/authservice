import { IAuthMongoDb, IAuthRepository } from "../repositories/AuthRepository"
import { isCheckClientBadRequestOk } from "../middlewares/errorCheck"
import { NextFunction, Request, Response } from "express"
import createError from 'http-errors'
import jwt, { JwtPayload, Secret } from 'jsonwebtoken'
import { IUser, User } from "../models/User"
import { ObjectId } from "mongoose"
import { RefreshToken } from "../models/refreshToken"
import CryptoJS , { AES } from "crypto-js"


export interface IAuthService {
  refreshToken(req: Request, res: Response, next: NextFunction): Promise<string | null>,
  loginUser(req: Request, res: Response, next: NextFunction): Promise<object | null>,
  logoutUser(req: Request, res: Response, next: NextFunction): void,
  registerUser(req: Request, res: Response, next: NextFunction): void
}

interface IPayloadUser {
  username: string,
  email: string,
  _id: string,
  iat: number,
  exp: number
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
    if (process.env.PRIVATE_KEY !== undefined) {
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
          expiresIn: process.env.ACCESS_TOKEN_LIFE
        })

          const tokenForRefresh = jwt.sign(payload, refreshToken, {
            expiresIn: process.env.REFRESH_TOKEN_LIFE
          })

          const tokens = {
            accessToken: accessToken,
            refreshToken: tokenForRefresh
          }

          await this.#authRepository.addRefreshTokenToDb(user.username, tokenForRefresh)

          return tokens
        }

        return null
      }
    }

    return null
  }

  async logoutUser(req: Request, res: Response, next: NextFunction) {
    const refreshTokenBasedOnUser = await this.#authRepository.getRefreshTokenBasedOnUserFromDb(req.body.username)
    if (process.env.ENCRYPTION_KEY && refreshTokenBasedOnUser?.toString()) {
      const decryptedRefreshTokenFromDb = AES.decrypt(refreshTokenBasedOnUser, process.env.ENCRYPTION_KEY).toString(CryptoJS.enc.Utf8)
      if(req.body.token === decryptedRefreshTokenFromDb) {
      
        this.#authRepository.deleteRefreshToken(req.body.username)
      } else {
        throw createError(400)
      }
    } else {
      throw createError(400)
    }
  }

  
async refreshToken(req: Request, res: Response, next: NextFunction): Promise<string | null> {
  console.log('ÖÖÖÖÖÖÖÖÖÖÖÖÖÖÖÖÖÖÖ')
  console.log(req.body)
  const refreshToken = req.body.refreshToken
  let accessToken = null

  if (refreshToken == null) {
    throw createError(401)
  }

  const refreshTokenBasedOnUser = await this.#authRepository.getRefreshTokenBasedOnUserFromDb(req.body.username)

  if (process.env.ENCRYPTION_KEY && refreshTokenBasedOnUser?.toString()) {
    const decryptedTokenBasedOnUser = AES.decrypt(refreshTokenBasedOnUser, process.env.ENCRYPTION_KEY).toString(CryptoJS.enc.Utf8)
    if(refreshToken !== decryptedTokenBasedOnUser) {
      throw createError(403, 'Forbidden: Invalid refreshtoken')
    }
  }

  if (process.env.REFRESH_TOKEN_SECRET) {
    try {
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