import { asClass, createContainer } from "awilix"
import { scopePerRequest } from "awilix-express"
import { Application } from "express"
import { AuthService, IAuthService } from "./services/AuthService"
import { AuthRepository, IAuthRepository } from "./repositories/AuthRepository"

export const loadContainer = (app: Application) => {
  const container = createContainer({
  injectionMode: 'CLASSIC'
  })
  .register<IAuthService>('AuthService', asClass(AuthService).scoped())
  .register<IAuthRepository>('AuthRepository', asClass(AuthRepository).scoped())

  app.use(scopePerRequest(container))
}