import express, { NextFunction, Request, Response } from "express"
import { loadContainer } from './container'
import helmet from 'helmet'
import { join } from 'node:path'
import path from 'path'
import { loadControllers } from 'awilix-express'
import { connectDataBase } from './config/mongoose.ts'

try {
  connectDataBase()

  const app = express()

  app.use(helmet.contentSecurityPolicy({
    directives: {
      ...helmet.contentSecurityPolicy.getDefaultDirectives(),
      'script-src': ["'self'", "'unsafe-inline'"],
      'style-src': ["'self'", "'unsafe-inline'"]
    }
  }))

  app.use(express.json())

  loadContainer(app)

  app.use(loadControllers(
    'controllers/*ts',
    { cwd: __dirname }  
  ))

  interface CustomError extends Error {
    status?: number
  }

  // Error handler.
  app.use(function (err: CustomError, req: Request, res: Response, next: NextFunction) {
    if (err.status === 400) {
      return res
        .status(400)
        .json({
          status_code: 400,
          message: 'The request cannot or will not be processed due to something that is perceived to be a client error (for example, validation error).'
        })
    } else if (err.status === 401) {
      return res
        .status(401)
        .json({
          status_code: 401,
          message: 'Credentials invalid or not provided.'
        })
    } else if (err.status === 409) {
      return res
        .sendStatus(409)
    } else if (err.status === 500) {
      return res
        .status(500)
        .json({
          status_code: 500,
          message: 'An unexpected condition was encountered.'
        })
    }

    if (req.app.get('env') !== 'development') {
      return res
        .status(err.status || 500)
        .json({
          status: err.status,
          message: err.message
        })
    }
  })

  app.listen(process.env.PORT, () => {
    console.log(`Server running at http://localhost:${process.env.PORT}`)
    console.log('Press Ctrl-C to terminate...')
  })


} catch (err) {
  console.error(err)
  process.exitCode = 1
}
