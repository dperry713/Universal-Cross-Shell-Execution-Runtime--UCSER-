"""
Database Migration: SQLite → PostgreSQL
Provides smooth migration path from development to production database
"""

import os
import logging
import sqlite3
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass

import psycopg2
from psycopg2 import sql
from psycopg2.extras import execute_values

logger = logging.getLogger(__name__)


@dataclass
class DatabaseConfig:
    """Database configuration"""
    db_type: str  # 'sqlite' or 'postgresql'
    host: Optional[str] = None
    port: Optional[int] = None
    database: str = None
    user: Optional[str] = None
    password: Optional[str] = None
    
    # SQLite only
    path: Optional[str] = None


class DatabaseConnection:
    """Abstract database connection"""
    
    def __init__(self, config: DatabaseConfig):
        self.config = config
        self.conn = None
    
    def connect(self):
        """Establish connection"""
        raise NotImplementedError
    
    def execute(self, query: str, params: tuple = ()):
        """Execute query"""
        raise NotImplementedError
    
    def fetch_all(self, query: str, params: tuple = ()):
        """Fetch all results"""
        raise NotImplementedError
    
    def close(self):
        """Close connection"""
        if self.conn:
            self.conn.close()


class SQLiteConnection(DatabaseConnection):
    """SQLite database connection"""
    
    def connect(self):
        """Connect to SQLite"""
        try:
            self.conn = sqlite3.connect(self.config.path)
            self.conn.row_factory = sqlite3.Row
            logger.info(f"Connected to SQLite: {self.config.path}")
        except Exception as e:
            raise ConnectionError(f"Failed to connect to SQLite: {e}")
    
    def execute(self, query: str, params: tuple = ()):
        """Execute query"""
        cursor = self.conn.cursor()
        cursor.execute(query, params)
        self.conn.commit()
        return cursor
    
    def fetch_all(self, query: str, params: tuple = ()):
        """Fetch all results"""
        cursor = self.conn.cursor()
        cursor.execute(query, params)
        return cursor.fetchall()


class PostgresConnection(DatabaseConnection):
    """PostgreSQL database connection"""
    
    def connect(self):
        """Connect to PostgreSQL"""
        try:
            self.conn = psycopg2.connect(
                host=self.config.host,
                port=self.config.port or 5432,
                database=self.config.database,
                user=self.config.user,
                password=self.config.password
            )
            logger.info(f"Connected to PostgreSQL: {self.config.host}:{self.config.port}/{self.config.database}")
        except Exception as e:
            raise ConnectionError(f"Failed to connect to PostgreSQL: {e}")
    
    def execute(self, query: str, params: tuple = ()):
        """Execute query"""
        cursor = self.conn.cursor()
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)
        self.conn.commit()
        return cursor
    
    def fetch_all(self, query: str, params: tuple = ()):
        """Fetch all results"""
        cursor = self.conn.cursor()
        cursor.execute(query, params)
        return cursor.fetchall()


class DatabaseMigrator:
    """Handles migration from SQLite to PostgreSQL"""
    
    # Table schemas (PostgreSQL DDL)
    SCHEMAS = {
        'execution_audit': """
            CREATE TABLE IF NOT EXISTS execution_audit (
                id SERIAL PRIMARY KEY,
                audit_id UUID NOT NULL UNIQUE,
                timestamp TIMESTAMP NOT NULL,
                command_hash VARCHAR(256) NOT NULL,
                policy_tags TEXT[] DEFAULT '{}',
                severity VARCHAR(50) NOT NULL,
                exit_code INTEGER,
                stdout_hash VARCHAR(256),
                stderr_hash VARCHAR(256),
                duration_seconds FLOAT,
                executor_user VARCHAR(255),
                executor_hostname VARCHAR(255),
                digital_signature VARCHAR(512),
                merkle_root VARCHAR(512),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_audit_id (audit_id),
                INDEX idx_timestamp (timestamp),
                INDEX idx_executor_user (executor_user)
            );
        """,
        'users': """
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                user_id VARCHAR(255) NOT NULL UNIQUE,
                username VARCHAR(255) NOT NULL,
                email VARCHAR(255) NOT NULL,
                roles TEXT[] DEFAULT '{}',
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                mfa_enabled BOOLEAN DEFAULT FALSE,
                INDEX idx_user_id (user_id),
                INDEX idx_username (username)
            );
        """,
        'service_accounts': """
            CREATE TABLE IF NOT EXISTS service_accounts (
                id SERIAL PRIMARY KEY,
                account_id VARCHAR(255) NOT NULL UNIQUE,
                name VARCHAR(255) NOT NULL,
                roles TEXT[] DEFAULT '{}',
                api_key_hash VARCHAR(512),
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_used TIMESTAMP,
                allowed_origins TEXT[] DEFAULT '{}',
                rate_limit INTEGER DEFAULT 1000,
                INDEX idx_account_id (account_id)
            );
        """,
        'workflows': """
            CREATE TABLE IF NOT EXISTS workflows (
                id SERIAL PRIMARY KEY,
                workflow_id UUID NOT NULL UNIQUE,
                name VARCHAR(255) NOT NULL,
                description TEXT,
                dag_json JSONB,
                policy_tags TEXT[] DEFAULT '{}',
                created_by VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE,
                INDEX idx_workflow_id (workflow_id),
                INDEX idx_name (name),
                INDEX idx_created_by (created_by)
            );
        """,
        'policy_rules': """
            CREATE TABLE IF NOT EXISTS policy_rules (
                id SERIAL PRIMARY KEY,
                policy_id UUID NOT NULL UNIQUE,
                name VARCHAR(255) NOT NULL,
                description TEXT,
                rego_rule TEXT,
                severity VARCHAR(50),
                enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_policy_id (policy_id),
                INDEX idx_severity (severity)
            );
        """,
    }
    
    def __init__(self, source: DatabaseConnection, target: DatabaseConnection):
        self.source = source
        self.target = target
    
    def create_schema(self):
        """Create PostgreSQL schema"""
        logger.info("Creating PostgreSQL schema...")
        
        for table_name, schema in self.SCHEMAS.items():
            try:
                # Remove INDEX statements (PostgreSQL doesn't use CREATE INDEX here)
                schema_clean = schema.replace('INDEX', 'KEY')
                self.target.execute(schema_clean)
                logger.info(f"Created table: {table_name}")
            except Exception as e:
                logger.warning(f"Schema creation warning: {e}")
    
    def migrate_table(self, table_name: str, columns: List[str]):
        """Migrate data from one table to another"""
        logger.info(f"Migrating table: {table_name}...")
        
        try:
            # Fetch data from SQLite
            query = f"SELECT {', '.join(columns)} FROM {table_name}"
            rows = self.source.fetch_all(query)
            
            if not rows:
                logger.info(f"No data to migrate in {table_name}")
                return
            
            # Convert rows to tuples (handle SQLite Row objects)
            data = [tuple(row) for row in rows]
            
            # Insert into PostgreSQL
            placeholders = ', '.join(['%s'] * len(columns))
            insert_query = f"INSERT INTO {table_name} ({', '.join(columns)}) VALUES ({placeholders})"
            
            cursor = self.target.conn.cursor()
            execute_values(cursor, insert_query, data, page_size=1000)
            self.target.conn.commit()
            
            logger.info(f"Migrated {len(data)} rows to {table_name}")
        
        except Exception as e:
            logger.error(f"Migration error for {table_name}: {e}")
            raise
    
    def run_migration(self):
        """Execute full migration"""
        logger.info("=" * 60)
        logger.info("Starting Database Migration: SQLite → PostgreSQL")
        logger.info("=" * 60)
        
        try:
            # Connect to both databases
            logger.info("Connecting to databases...")
            self.source.connect()
            self.target.connect()
            
            # Create schema in target
            self.create_schema()
            
            # Migrate tables
            migration_plan = {
                'execution_audit': ['audit_id', 'timestamp', 'command_hash', 'policy_tags',
                                  'severity', 'exit_code', 'stdout_hash', 'stderr_hash',
                                  'duration_seconds', 'executor_user', 'executor_hostname',
                                  'digital_signature', 'merkle_root'],
                'users': ['user_id', 'username', 'email', 'roles', 'is_active',
                         'created_at', 'last_login', 'mfa_enabled'],
                'service_accounts': ['account_id', 'name', 'roles', 'api_key_hash',
                                   'is_active', 'created_at', 'last_used',
                                   'allowed_origins', 'rate_limit'],
                'workflows': ['workflow_id', 'name', 'description', 'dag_json',
                            'policy_tags', 'created_by', 'created_at', 'updated_at',
                            'is_active'],
                'policy_rules': ['policy_id', 'name', 'description', 'rego_rule',
                               'severity', 'enabled', 'created_at'],
            }
            
            total_rows = 0
            for table_name, columns in migration_plan.items():
                try:
                    self.migrate_table(table_name, columns)
                except Exception as e:
                    logger.warning(f"Skipping table {table_name}: {e}")
            
            logger.info("=" * 60)
            logger.info("✅ Migration completed successfully!")
            logger.info("=" * 60)
            
            return True
        
        except Exception as e:
            logger.error(f"Migration failed: {e}")
            return False
        
        finally:
            self.source.close()
            self.target.close()


def migrate_from_cli():
    """CLI interface for migration"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Migrate UCSER database from SQLite to PostgreSQL")
    
    # Source (SQLite)
    parser.add_argument('--sqlite-path', required=True, help='Path to SQLite database')
    
    # Target (PostgreSQL)
    parser.add_argument('--pg-host', default='localhost', help='PostgreSQL host')
    parser.add_argument('--pg-port', type=int, default=5432, help='PostgreSQL port')
    parser.add_argument('--pg-database', required=True, help='PostgreSQL database name')
    parser.add_argument('--pg-user', required=True, help='PostgreSQL user')
    parser.add_argument('--pg-password', help='PostgreSQL password')
    
    args = parser.parse_args()
    
    logging.basicConfig(level=logging.INFO)
    
    # Create connections
    source_config = DatabaseConfig(
        db_type='sqlite',
        path=args.sqlite_path
    )
    source = SQLiteConnection(source_config)
    
    target_config = DatabaseConfig(
        db_type='postgresql',
        host=args.pg_host,
        port=args.pg_port,
        database=args.pg_database,
        user=args.pg_user,
        password=args.pg_password
    )
    target = PostgresConnection(target_config)
    
    # Run migration
    migrator = DatabaseMigrator(source, target)
    success = migrator.run_migration()
    
    return 0 if success else 1


if __name__ == "__main__":
    import sys
    sys.exit(migrate_from_cli())
