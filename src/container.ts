import { asClass, createContainer } from "awilix"
import { scopePerRequest } from "awilix-express"
import { Application } from "express"
import { TaskService, ITaskService } from "./services/TaskService"
import { UserService, IUserService } from "./services/UserService"
import { UserRepository, IUserRepository } from "./repositories/UserRepository"

export const loadContainer = (app: Application) => {
  const container = createContainer({
  injectionMode: 'CLASSIC'
  })
  .register<ITaskService>('TaskService', asClass(TaskService).scoped())
  .register<IUserService>('UserService', asClass(UserService).scoped())
  .register<IUserRepository>('UserRepository', asClass(UserRepository).scoped())

  app.use(scopePerRequest(container))
}