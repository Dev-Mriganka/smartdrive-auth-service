-- Create users table
CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    is_enabled BOOLEAN DEFAULT TRUE,
    is_account_non_expired BOOLEAN DEFAULT TRUE,
    is_account_non_locked BOOLEAN DEFAULT TRUE,
    is_credentials_non_expired BOOLEAN DEFAULT TRUE,
    last_login TIMESTAMP,
    failed_login_attempts INTEGER DEFAULT 0,
    account_locked_until TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Create roles table
CREATE TABLE roles (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Create user_roles junction table
CREATE TABLE user_roles (
    user_id BIGINT NOT NULL,
    role_id BIGINT NOT NULL,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
);

-- Create oauth2_clients table
CREATE TABLE oauth2_clients (
    id BIGSERIAL PRIMARY KEY,
    client_id VARCHAR(255) UNIQUE NOT NULL,
    client_secret VARCHAR(255) NOT NULL,
    client_name VARCHAR(255) NOT NULL,
    description TEXT,
    access_token_validity INTEGER,
    refresh_token_validity INTEGER,
    is_enabled BOOLEAN DEFAULT TRUE,
    is_confidential BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Create oauth2_client_redirect_uris table
CREATE TABLE oauth2_client_redirect_uris (
    client_id BIGINT NOT NULL,
    redirect_uri VARCHAR(500) NOT NULL,
    PRIMARY KEY (client_id, redirect_uri),
    FOREIGN KEY (client_id) REFERENCES oauth2_clients(id) ON DELETE CASCADE
);

-- Create oauth2_client_scopes table
CREATE TABLE oauth2_client_scopes (
    client_id BIGINT NOT NULL,
    scope VARCHAR(100) NOT NULL,
    PRIMARY KEY (client_id, scope),
    FOREIGN KEY (client_id) REFERENCES oauth2_clients(id) ON DELETE CASCADE
);

-- Create oauth2_client_grant_types table
CREATE TABLE oauth2_client_grant_types (
    client_id BIGINT NOT NULL,
    grant_type VARCHAR(50) NOT NULL,
    PRIMARY KEY (client_id, grant_type),
    FOREIGN KEY (client_id) REFERENCES oauth2_clients(id) ON DELETE CASCADE
);

-- Create refresh_tokens table
CREATE TABLE refresh_tokens (
    id BIGSERIAL PRIMARY KEY,
    token VARCHAR(500) UNIQUE NOT NULL,
    user_id BIGINT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    is_revoked BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at TIMESTAMP,
    client_id VARCHAR(255),
    scope TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create audit_logs table
CREATE TABLE audit_logs (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100),
    resource_id VARCHAR(255),
    details JSONB,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Insert default roles
INSERT INTO roles (name, description) VALUES
('SMARTDRIVE_ADMIN', 'Full system access'),
('SMARTDRIVE_USER', 'Personal file management'),
('SMARTDRIVE_VIEWER', 'Read-only access'),
('SMARTDRIVE_GUEST', 'Limited access');

-- Insert default OAuth2 clients
INSERT INTO oauth2_clients (client_id, client_secret, client_name, description, access_token_validity, refresh_token_validity) VALUES
('smartdrive-web', '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/HS.iK8i', 'SmartDrive Web Client', 'Web application client', 3600, 86400),
('smartdrive-api', '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/HS.iK8i', 'SmartDrive API Client', 'API service client', 3600, 86400);

-- Insert redirect URIs for web client
INSERT INTO oauth2_client_redirect_uris (client_id, redirect_uri) VALUES
(1, 'http://localhost:3000/callback'),
(1, 'http://localhost:8080/callback');

-- Insert scopes for clients
INSERT INTO oauth2_client_scopes (client_id, scope) VALUES
(1, 'read'),
(1, 'write'),
(2, 'read'),
(2, 'write'),
(2, 'admin');

-- Insert grant types for clients
INSERT INTO oauth2_client_grant_types (client_id, grant_type) VALUES
(1, 'authorization_code'),
(1, 'refresh_token'),
(2, 'client_credentials'),
(2, 'password'),
(2, 'refresh_token');

-- Create indexes for better performance
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_refresh_tokens_token ON refresh_tokens(token);
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX idx_oauth2_clients_client_id ON oauth2_clients(client_id);
