import { IAuthMongoDb, IAuthRepository } from "../repositories/AuthRepository"
import { isCheckClientBadRequestOk } from "../middlewares/errorCheck"
import { NextFunction, Request, Response } from "express"
import createError from 'http-errors'
import jwt, { JwtPayload, Secret } from 'jsonwebtoken'
import { IUser, User } from "../models/User"
import { ObjectId } from "mongoose"
import { RefreshToken } from "../models/refreshToken"
import CryptoJS, { AES } from "crypto-js"


export interface IAuthService {
  genereateNewRefreshAndAccessToken(req: Request, res: Response, next: NextFunction): Promise<ITokens | null>,
  generateRefreshAndAccessToken(req: Request, res: Response, next: NextFunction): Promise<object | null>,
  removeRefreshTokenBasedOnUser(req: Request, res: Response, next: NextFunction): void,
  registerUser(req: Request, res: Response, next: NextFunction): void
}

interface IPayloadUser {
  username: string,
  email: string,
  id: string,
  iat: number,
  exp: number
}

interface IPayloadUserAlt {
  username: string,
  email: string,
  id: string
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

  async generateRefreshAndAccessToken(req: Request, res: Response, next: NextFunction): Promise<ITokens | null> {
    if (process.env.PRIVATE_KEY !== undefined) {
      const token = Buffer.from(process.env.PRIVATE_KEY, 'base64')

      const refreshToken = process.env.REFRESH_TOKEN_SECRET
      if (refreshToken !== undefined) {

        const user: IUser | null = await this.#authRepository.loginUser(req, res, next)

        if (user) {
          const payload = {
            username: user.username,
            email: user.email,
            id: user._id.toString()
          }

          const accessToken = this.#generateAccessToken(payload, token)
          const tokenForRefresh = this.#generateRefreshToken(payload, refreshToken)

          await this.#authRepository.addRefreshTokenToDb(user.username, tokenForRefresh)

          return {
            accessToken: accessToken,
            refreshToken: tokenForRefresh
          }
        }

        return null
      }
    }

    return null
  }

  async removeRefreshTokenBasedOnUser(req: Request, res: Response, next: NextFunction) {
    const refreshTokenBasedOnUser = await this.#authRepository.getRefreshTokenBasedOnUserFromDb(req.body.username)

    if (process.env.ENCRYPTION_KEY && refreshTokenBasedOnUser?.toString()) {
      const decryptedRefreshTokenFromDb = AES.decrypt(refreshTokenBasedOnUser, process.env.ENCRYPTION_KEY).toString(CryptoJS.enc.Utf8)

      if (req.body.token === decryptedRefreshTokenFromDb) {
        await this.#authRepository.deleteRefreshToken(req.body.username)

      } else {
        throw createError(400)
      }
    } else {
      throw createError(400)
    }
  }

  async genereateNewRefreshAndAccessToken(req: Request, res: Response, next: NextFunction): Promise<ITokens | null> {
    const refreshToken = req.body.refreshToken
    let accessToken = null
    let newRefreshToken = null
    const refreshTokenBasedOnUser = await this.#authRepository.getRefreshTokenBasedOnUserFromDb(req.body.username)

    this.#checkIfRefreshTokenIsNull(refreshToken)
    this.#checkIfRefreshTokenMatchesInDb(refreshTokenBasedOnUser?.toString(), refreshToken)

    if (process.env.REFRESH_TOKEN_SECRET) {
      try {
        const decoded = jwt.verify(
          refreshToken,
          process.env.REFRESH_TOKEN_SECRET
        ) as IPayloadUser

        const payload = {
          username: decoded.username,
          email: decoded.email,
          id: decoded.id
        }

        if (process.env.PRIVATE_KEY) {
          const token = Buffer.from(process.env.PRIVATE_KEY, 'base64')
          accessToken = this.#generateAccessToken(payload, token)
          newRefreshToken = this.#generateRefreshToken(payload, process.env.REFRESH_TOKEN_SECRET)

          await this.#authRepository.deleteRefreshToken(req.body.username)
          await this.#authRepository.addRefreshTokenToDb(req.body.username, newRefreshToken)

          return { accessToken: accessToken, refreshToken: newRefreshToken }
        }
      } catch (err) {
        throw createError(403, 'Forbidden: Invalid refreshToken')
      }
    } else {
      throw createError(500)
    }

    return null
  }

  #checkIfRefreshTokenIsNull(refreshToken: string) {
    if (refreshToken == null) {
      throw createError(401)
    }
  }

  #checkIfRefreshTokenMatchesInDb(refreshTokenBasedOnUser: string | undefined, refreshToken: string) {
    if (process.env.ENCRYPTION_KEY && refreshTokenBasedOnUser?.toString()) {
      const decryptedTokenBasedOnUser = AES.decrypt(refreshTokenBasedOnUser, process.env.ENCRYPTION_KEY).toString(CryptoJS.enc.Utf8)

      if (refreshToken !== decryptedTokenBasedOnUser) {
        throw createError(403, 'Forbidden: Invalid refreshtoken')
      }
    }
  }

  #generateAccessToken(payload: IPayloadUserAlt, token: Secret) {
    const accessToken = jwt.sign(payload, token, {
      algorithm: 'RS256',
      expiresIn: process.env.ACCESS_TOKEN_LIFE
    })

    return accessToken
  }

  #generateRefreshToken(payload: IPayloadUserAlt, token: Secret) {
    return jwt.sign(payload, token, {
      expiresIn: process.env.REFRESH_TOKEN_LIFE
    })
  }

  #handleValidationErrorRegister(error: any) {
    if (error.code === 11000) {
      throw createError(400, 'This username or email is already in use. Please choose a different username or use a different email address.')
    } else if (error.errors.password.path === 'password') {
      throw createError(400, error.errors.password.message)
    } else {
      throw error
    }
  }
}