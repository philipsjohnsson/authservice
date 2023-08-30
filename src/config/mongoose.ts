import mongoose from 'mongoose'

/**
 * Establishes a connection to a database.
 *
 * @returns {Promise} Resolves to this if connection succeeded.
 */
export const connectDataBase = () => {
  const { connection } = mongoose

  // Bind connection to events (to get notifications).
  connection.on('connected', () => console.log('MongoDB connection opened.'))
  connection.on('error', err => console.error(`MongoDB connection error occurred: ${err}`))
  connection.on('disconnected', () => console.log('MongoDB is disconnected.'))

  // If the Node.js process ends, close the connection.
  process.on('SIGINT', async () => {
    try {
    await connection.close()
    console.log('MongoDB disconnected due to application termination.')
    } catch (err) {
      console.error('Error while closing MongoDB connection:', err)
      process.exit(1)
    }
  })

  // Connect to the server.
  if(process.env.DB_CONNECTION_STRING) {
    return mongoose.connect(process.env.DB_CONNECTION_STRING)
  }
}