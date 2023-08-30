export interface ITaskService {
  taskTest(): void
}

export class TaskService implements ITaskService {

  constructor() {
  
  }

  taskTest() {
    console.log('TEST TASK')
  }
}