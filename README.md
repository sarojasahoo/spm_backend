# Stock Portfolio Management Service

This microservice manages user investment portfolios, holdings, and transactions.
Built with **Spring Boot, JWT Authentication , WebFlux, and MySQL**.

## Features
- User Portfolio Management (login and register)
- Stock list (This is the list of scrips )
- Transaction Logging (BUY/SELL)
- Global Exception Handling
- Portfolio Overview with details of holding and capability to add and remove from holdings
- Scheduler is there to update the real time stock price. Please un-comment it while running the applciation once the application is fully ready and you 
  can change it in PortfolioScheduler at line 22. We have commented as the free api from AplhaVantage has limit of 25 hits per day per key. This is used to calculate the total portfoloi evaluation. Please uncomment once you are ready to observe the Portfolio evaluation.
- The search also uses AlphaVantage key for search the scrip symbols.
- SecurityConfig needs to be changed with angular application base url to allow angular aaplication.
    
## Tech Stack
- **Backend:** Java 17, Spring Boot 3.4.3, Spring WebFlux
- **FrontEnd** Angular CLI version 13.3.4
- **Database:** MySQL 8.x 
- **Build Tool:** Maven

## Database Schema
Schema Name: `spm_db`

###  Tables Overview
| Table Name           | Description                             |
|----------------------|-----------------------------------------|
| `users`              | Stores user details                     |
| `portfolios`         | Manages user investment accounts        |
| `transactions_audit` | Stores trade history (BUY/SELL)         |
| `stock_list`         | Lists all the stocks in user stock list |



---
### Table Creation SQL Scripts
#### 1️⃣ **Users Table**
```sql
CREATE TABLE IF NOT EXISTS users (
    user_id VARCHAR(36) PRIMARY KEY,  
    user_name VARCHAR(60) UNIQUE NOT NULL,
    user_email VARCHAR(60) UNIQUE NOT NULL,
    phone_number VARCHAR(15) NOT NULL,
    password VARCHAR(300) NOT NULL,
    active BOOLEAN NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

 2️⃣ **Portfolios Table**
CREATE TABLE portfolios (
    portfolio_id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(50) NOT NULL,
    total_value DECIMAL(19,4) DEFAULT NULL,
    stock_symbol VARCHAR(50) DEFAULT NULL,
    buy_price DECIMAL(19,4) DEFAULT NULL,
    quantity INT DEFAULT NULL,
    current_price DECIMAL(19,4) DEFAULT NULL,
    profit_loss DECIMAL(19,4) DEFAULT NULL,
    CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users(user_id)
) ;

 3️⃣ **StockList Table**
CREATE TABLE stock_list (
    stock_id SERIAL PRIMARY KEY,
    user_id VARCHAR(50) NOT NULL,
    stock_symbol VARCHAR(20) NOT NULL,
    open_price DECIMAL(10, 2),
    high_price DECIMAL(10, 2),
    low_price DECIMAL(10, 2),
    current_price DECIMAL(10, 2),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

 4️⃣ **Transactions Table**
CREATE TABLE transactions_audit (
  transaction_id BIGINT AUTO_INCREMENT PRIMARY KEY,
  user_id VARCHAR(255) NOT NULL,
  stock_symbol VARCHAR(100) NOT NULL,
  operation_type VARCHAR(50) NOT NULL,
  quantity INT NOT NULL,
  price DECIMAL(19,2) NOT NULL,
  transaction_date DATETIME NOT NULL,
  CONSTRAINT fk_user_id FOREIGN KEY (user_id) REFERENCES users(user_id)
);

---
### How to Set Up the Database 

CREATE DATABASE spm_db;
USE spm_db;
SOURCE schema.sql;  -- Import tables from SQL file
Change the application.yml file with the connections


Swagger uri
http://localhost:8080/swagger-ui/index.html
To use stock portfolio management apis please generate the authtoken and then call the apis.

Angular Changes
Please change the backend url in Angular front end applciation in environment.ts file.


### Further imporvments 
- There is less logging. If required it can be added.
- Api gateway can be added
- More testcases to add from ui and backend
- user roles and profiles can be added also.
- the applciation is using ROLE_USER  
