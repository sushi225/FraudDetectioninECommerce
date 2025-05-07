-- Database schema for Fraud Detection in E-Commerce

-- User Table
CREATE TABLE User (
    id BIGINT NOT NULL AUTO_INCREMENT,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('admin','seller','buyer') NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id)
);

-- Product Table
CREATE TABLE Product (
    id BIGINT NOT NULL AUTO_INCREMENT,
    seller_id BIGINT NOT NULL,
    name VARCHAR(255) NOT NULL,
    price_cents BIGINT NOT NULL,
    quantity INT NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    FOREIGN KEY (seller_id) REFERENCES User(id) ON DELETE CASCADE
);

-- Payment Table (Defined before Order due to potential FK cycle, though Order's FK is nullable)
-- Note: This structure assumes Payment is created *after* Order is initiated.
-- If Payment needs to exist before Order is finalized, the schema might need adjustment.
CREATE TABLE Payment (
    id BIGINT NOT NULL AUTO_INCREMENT,
    order_id BIGINT NOT NULL, -- Will add FK constraint after Order table is created if needed, but MySQL handles forward references.
    amount_cents BIGINT NOT NULL,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id)
    -- FK to Order added below after Order table definition
);

-- Order Table
CREATE TABLE `Order` ( -- Using backticks as Order is a reserved keyword
    id BIGINT NOT NULL AUTO_INCREMENT,
    user_id BIGINT NOT NULL,
    total_amount_cents BIGINT NOT NULL,
    payment_id BIGINT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    FOREIGN KEY (user_id) REFERENCES User(id) ON DELETE CASCADE,
    FOREIGN KEY (payment_id) REFERENCES Payment(id) ON DELETE SET NULL
);

-- Add FK constraint from Payment to Order now that Order exists
ALTER TABLE Payment
ADD CONSTRAINT fk_payment_order
FOREIGN KEY (order_id) REFERENCES `Order`(id) ON DELETE CASCADE;


-- Cart Table
CREATE TABLE Cart (
    id BIGINT NOT NULL AUTO_INCREMENT,
    user_id BIGINT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    FOREIGN KEY (user_id) REFERENCES User(id) ON DELETE CASCADE
);

-- Transaction Table
CREATE TABLE Transaction (
    id BIGINT NOT NULL AUTO_INCREMENT,
    buyer_id BIGINT NOT NULL,
    seller_id BIGINT NOT NULL,
    product_id BIGINT NOT NULL,
    amount_cents BIGINT NOT NULL,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    FOREIGN KEY (buyer_id) REFERENCES User(id) ON DELETE CASCADE,
    FOREIGN KEY (seller_id) REFERENCES User(id) ON DELETE CASCADE,
    FOREIGN KEY (product_id) REFERENCES Product(id) ON DELETE CASCADE
);

-- Review Table
CREATE TABLE Review (
    id BIGINT NOT NULL AUTO_INCREMENT,
    order_id BIGINT NULL, # Made nullable as a workaround
    buyer_id BIGINT NOT NULL,
    product_id BIGINT NOT NULL,
    rating INT NOT NULL CHECK (rating >= 1 AND rating <= 5), -- Added CHECK constraint for rating
    text TEXT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    FOREIGN KEY (order_id) REFERENCES `Order`(id) ON DELETE CASCADE,
    FOREIGN KEY (buyer_id) REFERENCES User(id) ON DELETE CASCADE,
    FOREIGN KEY (product_id) REFERENCES Product(id) ON DELETE CASCADE
);

-- CustomerSupport Table
CREATE TABLE CustomerSupport (
    id BIGINT NOT NULL AUTO_INCREMENT,
    buyer_id BIGINT NOT NULL,
    order_id BIGINT NULL,
    issue_type VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    status ENUM('open', 'in_progress', 'resolved', 'closed') NOT NULL DEFAULT 'open',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    FOREIGN KEY (buyer_id) REFERENCES User(id) ON DELETE CASCADE,
    FOREIGN KEY (order_id) REFERENCES `Order`(id) ON DELETE SET NULL
);

-- Blacklist Table
CREATE TABLE Blacklist (
    id BIGINT NOT NULL AUTO_INCREMENT,
    user_id BIGINT NOT NULL,
    blocked_until DATETIME NULL,
    reason TEXT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    FOREIGN KEY (user_id) REFERENCES User(id) ON DELETE CASCADE
);

-- LoggingActivity Table
CREATE TABLE LoggingActivity (
    id BIGINT NOT NULL AUTO_INCREMENT,
    user_id BIGINT NULL,
    action VARCHAR(255) NOT NULL,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    details TEXT NULL,
    PRIMARY KEY (id),
    FOREIGN KEY (user_id) REFERENCES User(id) ON DELETE SET NULL
);

-- AnomalyDetectionLog Table
CREATE TABLE AnomalyDetectionLog (
    id BIGINT NOT NULL AUTO_INCREMENT,
    event_type VARCHAR(255) NOT NULL,
    reference_id BIGINT NULL, -- Cannot add FK as it refers to multiple tables
    rule_triggered VARCHAR(255) NOT NULL,
    score DECIMAL(5,2) NULL,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id)
);

-- Wallet Table
CREATE TABLE Wallet (
    id BIGINT NOT NULL AUTO_INCREMENT,
    user_id BIGINT NOT NULL UNIQUE,
    balance_cents BIGINT NOT NULL DEFAULT 0,
    last_updated TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    FOREIGN KEY (user_id) REFERENCES User(id) ON DELETE CASCADE
);