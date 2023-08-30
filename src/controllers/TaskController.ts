import { GET, route } from 'awilix-express'
import { TaskService } from '../services/TaskService'
import { NextFunction, Request, Response } from "express"

@route('/')
export class TaskController {
  constructor(private TaskService: TaskService) {
    this.TaskService = TaskService
  }

  @GET()
  test(req: Request, res: Response, next: NextFunction) {
    console.log('TEST WE ARE INSIDE OF "/"')
    res.send('WE ARE INSIDE OF THIS')
  }
  
  @route('om')
  @GET()
  om(req: Request, res: Response, next: NextFunction) {
    console.log('TEST WE ARE INSIDE OF "/"')
    res.send('WE ARE INSIDE OF OM')
  }
}