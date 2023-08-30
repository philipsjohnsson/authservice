import { NextFunction, Request, Response } from "express"
// import { ILoginDetails } from "../services/UserService"
import createError from 'http-errors'

export function isCheckClientBadRequestOk (req: Request, res: Response, next: NextFunction) {
  if(req.body.username === undefined || req.body.email === undefined || req.body.password === undefined) {
    throw createError(400)
  }
}