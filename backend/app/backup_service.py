"""Automated Backup and Restore Service"""
import os
import subprocess
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, List
from sqlalchemy.orm import Session
from . import models
import json


class BackupService:
    """Handle database backups and restores"""
    
    def __init__(self, backup_dir: str = "/backups"):
        self.backup_dir = Path(backup_dir)
        self.backup_dir.mkdir(parents=True, exist_ok=True)
    
    def create_backup(self, db_url: str, backup_name: Optional[str] = None) -> dict:
        """Create database backup"""
        try:
            if not backup_name:
                backup_name = f"backup_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
            
            backup_path = self.backup_dir / f"{backup_name}.sql"
            
            # Extract connection details from SQLAlchemy URL
            # Format: postgresql://user:pass@host:port/dbname
            import re
            match = re.match(r'postgresql://([^:]+):([^@]+)@([^:]+):(\d+)/(.+)', db_url)
            if not match:
                raise ValueError("Invalid database URL format")
            
            user, password, host, port, dbname = match.groups()
            
            # Set PGPASSWORD environment variable
            env = os.environ.copy()
            env['PGPASSWORD'] = password
            
            # Run pg_dump
            cmd = [
                'pg_dump',
                '-h', host,
                '-p', port,
                '-U', user,
                '-d', dbname,
                '-F', 'c',  # Custom format
                '-f', str(backup_path),
            ]
            
            result = subprocess.run(
                cmd,
                env=env,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
            )
            
            if result.returncode != 0:
                raise Exception(f"pg_dump failed: {result.stderr}")
            
            # Create backup metadata
            metadata = {
                "backup_name": backup_name,
                "backup_path": str(backup_path),
                "created_at": datetime.utcnow().isoformat(),
                "size_bytes": backup_path.stat().st_size,
            }
            
            metadata_path = self.backup_dir / f"{backup_name}.meta.json"
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            return {
                "status": "success",
                "backup_name": backup_name,
                "backup_path": str(backup_path),
                "size_bytes": backup_path.stat().st_size,
            }
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
            }
    
    def restore_backup(self, backup_name: str, db_url: str) -> dict:
        """Restore database from backup"""
        try:
            backup_path = self.backup_dir / f"{backup_name}.sql"
            
            if not backup_path.exists():
                raise FileNotFoundError(f"Backup file not found: {backup_path}")
            
            # Extract connection details
            import re
            match = re.match(r'postgresql://([^:]+):([^@]+)@([^:]+):(\d+)/(.+)', db_url)
            if not match:
                raise ValueError("Invalid database URL format")
            
            user, password, host, port, dbname = match.groups()
            
            # Set PGPASSWORD
            env = os.environ.copy()
            env['PGPASSWORD'] = password
            
            # Drop and recreate database (WARNING: destructive)
            # In production, you might want to restore to a different database first
            drop_cmd = [
                'psql',
                '-h', host,
                '-p', port,
                '-U', user,
                '-d', 'postgres',  # Connect to postgres DB to drop target DB
                '-c', f'DROP DATABASE IF EXISTS {dbname};',
            ]
            
            create_cmd = [
                'psql',
                '-h', host,
                '-p', port,
                '-U', user,
                '-d', 'postgres',
                '-c', f'CREATE DATABASE {dbname};',
            ]
            
            restore_cmd = [
                'pg_restore',
                '-h', host,
                '-p', port,
                '-U', user,
                '-d', dbname,
                '-c',  # Clean (drop) before restore
                str(backup_path),
            ]
            
            # Execute commands
            for cmd in [drop_cmd, create_cmd, restore_cmd]:
                result = subprocess.run(
                    cmd,
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=600,  # 10 minute timeout
                )
                if result.returncode != 0:
                    raise Exception(f"Command failed: {result.stderr}")
            
            return {
                "status": "success",
                "message": f"Database restored from {backup_name}",
            }
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
            }
    
    def list_backups(self) -> List[dict]:
        """List all available backups"""
        backups = []
        for meta_file in self.backup_dir.glob("*.meta.json"):
            try:
                with open(meta_file, 'r') as f:
                    metadata = json.load(f)
                    backups.append(metadata)
            except Exception:
                continue
        
        return sorted(backups, key=lambda x: x.get("created_at", ""), reverse=True)
    
    def cleanup_old_backups(self, keep_days: int = 30):
        """Remove backups older than keep_days"""
        cutoff = datetime.utcnow() - timedelta(days=keep_days)
        deleted = []
        
        for meta_file in self.backup_dir.glob("*.meta.json"):
            try:
                with open(meta_file, 'r') as f:
                    metadata = json.load(f)
                    created_at = datetime.fromisoformat(metadata.get("created_at", ""))
                    
                    if created_at < cutoff:
                        backup_name = metadata.get("backup_name")
                        # Delete backup file and metadata
                        backup_file = self.backup_dir / f"{backup_name}.sql"
                        if backup_file.exists():
                            backup_file.unlink()
                        meta_file.unlink()
                        deleted.append(backup_name)
            except Exception:
                continue
        
        return deleted

