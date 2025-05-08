-- SQL DDL Statements for Anomaly Detection and Blacklisting System

-- -----------------------------------------------------
-- Core E-commerce Tables
-- -----------------------------------------------------

-- Order Table
CREATE TABLE IF NOT EXISTS `Order` (
  `id` BIGINT NOT NULL AUTO_INCREMENT,
  `buyer_id` BIGINT NOT NULL,
  `order_date` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `total_amount_cents` INT NOT NULL DEFAULT 0,
  `status` ENUM('pending', 'processing', 'shipped', 'completed', 'cancelled', 'refunded') NOT NULL DEFAULT 'pending',
  PRIMARY KEY (`id`),
  INDEX `idx_order_buyer_date` (`buyer_id` ASC, `order_date` DESC),
  CONSTRAINT `fk_order_buyer`
    FOREIGN KEY (`buyer_id`)
    REFERENCES `User` (`id`)
    ON DELETE CASCADE
);

-- Transaction Table (Order Items)
CREATE TABLE IF NOT EXISTS `Transaction` (
  `id` BIGINT NOT NULL AUTO_INCREMENT,
  `order_id` BIGINT NOT NULL,
  `product_id` BIGINT NOT NULL,
  `quantity` INT NOT NULL,
  `price_at_transaction_cents` INT NOT NULL COMMENT 'Price of the product at the time of this transaction item',
  PRIMARY KEY (`id`),
  INDEX `idx_transaction_order` (`order_id` ASC),
  INDEX `idx_transaction_product` (`product_id` ASC),
  CONSTRAINT `fk_transaction_order`
    FOREIGN KEY (`order_id`)
    REFERENCES `Order` (`id`)
    ON DELETE CASCADE,
  CONSTRAINT `fk_transaction_product`
    FOREIGN KEY (`product_id`)
    REFERENCES `Product` (`id`)
    ON DELETE RESTRICT -- Assuming products should exist for a transaction to be valid
);
-- -----------------------------------------------------
-- New Tables for Event Logging
-- -----------------------------------------------------

-- To log user login attempts
CREATE TABLE IF NOT EXISTS `login_attempts` (
  `id` BIGINT NOT NULL AUTO_INCREMENT,
  `user_id` BIGINT NOT NULL,
  `login_timestamp` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `ip_address` VARCHAR(45) NULL,
  `success` BOOLEAN NULL, -- True for successful, False for failed, NULL if not tracked
  PRIMARY KEY (`id`),
  INDEX `idx_login_attempts_user_timestamp` (`user_id` ASC, `login_timestamp` DESC),
  CONSTRAINT `fk_login_attempts_user`
    FOREIGN KEY (`user_id`)
    REFERENCES `User` (`id`)
    ON DELETE CASCADE
);

-- To log cart add/remove events for cart flipping detection
CREATE TABLE IF NOT EXISTS `cart_events` (
  `id` BIGINT NOT NULL AUTO_INCREMENT,
  `buyer_id` BIGINT NOT NULL,
  `cart_id` BIGINT NULL, -- FK to Cart.id
  `product_id` BIGINT NOT NULL, -- FK to Product.id
  `quantity_changed` INT NOT NULL DEFAULT 1 COMMENT 'Positive for add, negative for remove if tracking net changes, or always positive if event_type dictates action',
  `event_type` ENUM('add', 'remove') NOT NULL,
  `event_timestamp` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  INDEX `idx_cart_events_buyer_timestamp` (`buyer_id` ASC, `event_timestamp` DESC),
  CONSTRAINT `fk_cart_events_buyer`
    FOREIGN KEY (`buyer_id`)
    REFERENCES `User` (`id`)
    ON DELETE CASCADE,
  CONSTRAINT `fk_cart_events_product`
    FOREIGN KEY (`product_id`)
    REFERENCES `Product` (`id`)
    ON DELETE CASCADE,
  CONSTRAINT `fk_cart_events_cart`
    FOREIGN KEY (`cart_id`)
    REFERENCES `Cart` (`id`)
    ON DELETE SET NULL -- Or CASCADE if events are strictly tied to cart lifecycle
);

-- -----------------------------------------------------
-- New Table for Detected Anomalies
-- -----------------------------------------------------

CREATE TABLE IF NOT EXISTS `detected_anomalies` (
  `anomaly_id` BIGINT NOT NULL AUTO_INCREMENT,
  `user_id` BIGINT NOT NULL COMMENT 'User associated with the anomaly (buyer or seller)',
  `user_type` ENUM('buyer', 'seller') NOT NULL,
  `anomaly_type` VARCHAR(255) NOT NULL COMMENT 'e.g., multiple_logins, rapid_transactions, cart_flipping, poor_reviews_seller, item_not_received_buyer',
  `detection_timestamp` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `details` TEXT NULL COMMENT 'JSON or textual details about the event (e.g., count, timeframe, specific IDs involved)',
  PRIMARY KEY (`anomaly_id`),
  INDEX `idx_detected_anomalies_user_time` (`user_id` ASC, `detection_timestamp` DESC),
  INDEX `idx_detected_anomalies_type` (`anomaly_type` ASC),
  CONSTRAINT `fk_detected_anomalies_user`
    FOREIGN KEY (`user_id`)
    REFERENCES `User` (`id`)
    ON DELETE CASCADE -- If user is deleted, their anomaly logs are also deleted.
);

-- -----------------------------------------------------
-- New Table for Blacklisted Users
-- -----------------------------------------------------
DROP TABLE IF EXISTS `Blacklist`; -- Removing old Blacklist table as per new requirements

CREATE TABLE IF NOT EXISTS `blacklisted_users` (
  `user_id` BIGINT NOT NULL COMMENT 'The original User.id. This is the PRIMARY KEY.',
  `email` VARCHAR(255) NOT NULL UNIQUE COMMENT 'Copied email from User table, kept unique.',
  `password_hash` VARCHAR(255) NULL COMMENT 'Copied password_hash from User table. Can be NULL if external auth or if we dont want to store it.',
  `original_role` ENUM('buyer', 'seller') NOT NULL COMMENT 'Role at the time of blacklisting (admin cannot be blacklisted).',
  `blacklist_timestamp` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `reason` TEXT NULL COMMENT 'e.g., accumulated_2_anomalies, manual_admin_blacklist_X_reason',
  `blacklisted_by_admin_id` BIGINT NULL COMMENT 'User.id of admin if manually blacklisted',
  PRIMARY KEY (`user_id`),
  CONSTRAINT `fk_blacklisted_users_admin`
    FOREIGN KEY (`blacklisted_by_admin_id`)
    REFERENCES `User` (`id`)
    ON DELETE SET NULL -- If admin who blacklisted is deleted, we keep the record but nullify the admin_id.
);

-- -----------------------------------------------------
-- Table for General Activity Logging
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `activity_log` (
  `id` BIGINT NOT NULL AUTO_INCREMENT,
  `user_id` BIGINT NULL, -- Allow NULL if activity is not user-specific (e.g., system event)
  `action` VARCHAR(255) NOT NULL COMMENT 'Description of the action performed',
  `timestamp` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `details` TEXT NULL COMMENT 'Additional details about the activity, can be JSON or text',
  PRIMARY KEY (`id`),
  INDEX `idx_activity_log_user_timestamp` (`user_id` ASC, `timestamp` DESC),
  INDEX `idx_activity_log_timestamp` (`timestamp` DESC),
  CONSTRAINT `fk_activity_log_user`
    FOREIGN KEY (`user_id`)
    REFERENCES `User` (`id`)
    ON DELETE SET NULL -- If user is deleted, keep activity log but nullify user_id
);

-- -----------------------------------------------------
-- Modifications to Existing Tables
-- -----------------------------------------------------

-- Modify User Table:
ALTER TABLE `User`
-- ADD COLUMN `status` ENUM('active', 'suspended', 'blacklisted') NOT NULL DEFAULT 'active' AFTER `role`,
MODIFY COLUMN `password_hash` VARCHAR(255) NULL COMMENT 'Set to NULL if user is blacklisted and credentials moved to blacklisted_users table. Original password_hash is in blacklisted_users.';
-- ADD INDEX `idx_user_status` (`status`);

-- Modify Review Table:
-- ALTER TABLE `Review`
-- ADD COLUMN `seller_id` BIGINT NULL COMMENT 'The User.id of the seller of the product being reviewed. To be populated via trigger or application logic.' AFTER `product_id`,
-- ADD INDEX `idx_review_seller_rating_time` (`seller_id` ASC, `rating` ASC, `created_at` DESC),
-- ADD CONSTRAINT `fk_review_seller`
--  FOREIGN KEY (`seller_id`)
--  REFERENCES `User` (`id`)
--  ON DELETE CASCADE;

-- Trigger to populate Review.seller_id (Example for MySQL)
-- Drop existing triggers if they exist to avoid errors on re-creation
DROP TRIGGER IF EXISTS `trg_review_before_insert_set_seller`;
DROP TRIGGER IF EXISTS `trg_review_before_update_set_seller`;

DELIMITER //
CREATE TRIGGER `trg_review_before_insert_set_seller`
BEFORE INSERT ON `Review`
FOR EACH ROW
BEGIN
  IF NEW.product_id IS NOT NULL THEN
    SELECT `P`.`seller_id` INTO @seller_id_val FROM `Product` `P` WHERE `P`.`id` = NEW.product_id;
    SET NEW.seller_id = @seller_id_val;
  END IF;
END//

CREATE TRIGGER `trg_review_before_update_set_seller`
BEFORE UPDATE ON `Review`
FOR EACH ROW
BEGIN
  IF NEW.product_id IS NOT NULL AND (OLD.product_id IS NULL OR NEW.product_id != OLD.product_id) THEN
    SELECT `P`.`seller_id` INTO @seller_id_val FROM `Product` `P` WHERE `P`.`id` = NEW.product_id;
    SET NEW.seller_id = @seller_id_val;
  ELSEIF NEW.product_id IS NULL THEN
    SET NEW.seller_id = NULL;
  END IF;
END//
DELIMITER ;

-- Modify CustomerSupport Table:
-- ALTER TABLE `CustomerSupport`
-- ADD INDEX `idx_customersupport_buyer_issue_time` (`buyer_id` ASC, `issue_type` ASC, `created_at` DESC);

-- Modify Product Table:
-- ALTER TABLE `Product`
-- ADD COLUMN `stock_quantity` INT NOT NULL DEFAULT 0 COMMENT 'Available stock for the product' AFTER `price_cents`; -- Assuming price_cents is a common column to place it after

-- Remove AnomalyDetectionLog if `detected_anomalies` covers its purpose.
DROP TABLE IF EXISTS `AnomalyDetectionLog`;