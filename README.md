# Auth service



## Implementation of refresh token explained
När en användare loggar in så skapas en access_token och en refresh_token. Alla refresh_tokens som är kopplade till den inloggade användaren tas bort från refresh_token databasen.

När en användare loggar ut så tas refresh_token som är knuten till den specifika användaren bort från refresh_token databasen.

När en användares access_token expires kan den förnyas med hjälp av refresh_tokenen.

Refresh_tokens på databasen är krypterade.




Refresh_token som genereras är för nu känslig för att läcka ut till andra användare, säkerhetsåtgärder bör tillämpas för detta.

* ATT GÖRA: 

När en access_token förnyas bör också en refresh_token förnyas.

Skriva om SOLID, dependency injection

Skriva klart hela README-filen.