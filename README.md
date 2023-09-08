# Authentication Service Readme

## Description
This is an authentication service that provides essential authentication functionalities such as login, logout, registration and refresh tokens.

## Preparations
Before running the authentication service, make sure to configure the following settings in the `.env` file:

- `DB_CONNECTION_STRING`: Set the database connection string.
- `PORT`: Specify the port on which the service will run.
- `PRIVATE_KEY`: Set the private key for access token generation. (token should be a token pair, RS256, one public for client)
- `ACCESS_TOKEN_LIFE`: Recommend setting the access token lifespan (e.g., around 5 minutes).
- `REFRESH_TOKEN_LIFE`: Recommend setting the refresh token lifespan (e.g., 1 day).
- `REFRESH_TOKEN_SECRET`: Configure the refresh token secret. (for now its not a key pair, Consider using an asymmetric public/private key pair for added security)
- `ENCRYPTION_KEY`: Define the encryption key used for encryption with AES.

## Installation
To install the required dependencies, run the following command:

```bash
npm install
```

Getting Started

To start the authentication service in development, execute the following command:

```bash
npm run dev
```