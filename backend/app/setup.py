"""Setup Wizard - First-time configuration"""
from sqlalchemy.orm import Session
from sqlalchemy import text
from typing import Optional
from . import models
from .auth import hash_password
from datetime import datetime


class SetupWizard:
    """Handle first-time setup"""
    
    @staticmethod
    def is_setup_complete(db: Session) -> bool:
        """Check if setup is already completed"""
        # Check if admin user exists
        admin_user = db.query(models.User).filter_by(role="admin").first()
        return admin_user is not None
    
    @staticmethod
    def create_admin_user(
        db: Session,
        email: str,
        password: str,
    ) -> models.User:
        """Create admin user during setup"""
        # Check if user already exists
        existing = db.query(models.User).filter_by(email=email).first()
        if existing:
            raise ValueError("User already exists")
        
        user = models.User(
            email=email,
            password_hash=hash_password(password),
            role="admin",
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return user
    
    @staticmethod
    def create_default_organization(db: Session, name: str = "Default Organization") -> models.Organization:
        """Create default organization"""
        org = db.query(models.Organization).filter_by(name=name).first()
        if org:
            return org
        
        org = models.Organization(name=name)
        db.add(org)
        db.commit()
        db.refresh(org)
        return org
    
    @staticmethod
    def test_database_connection(db: Session) -> dict:
        """Test database connection"""
        try:
            db.execute(text("SELECT 1"))
            db.commit()
            return {
                "status": "success",
                "message": "Database connection successful",
            }
        except Exception as e:
            return {
                "status": "error",
                "message": f"Database connection failed: {str(e)}",
            }
    
    @staticmethod
    def get_database_info(db: Session) -> dict:
        """Get database information"""
        try:
            # Check if SQLite or PostgreSQL
            db_url = str(db.bind.url)
            if 'sqlite' in db_url.lower():
                # SQLite
                result = db.execute(text("SELECT sqlite_version()"))
                version = result.scalar()
                result = db.execute(text("""
                    SELECT COUNT(*) FROM sqlite_master WHERE type='table'
                """))
                table_count = result.scalar()
                return {
                    "status": "success",
                    "version": f"SQLite {version}" if version else "SQLite Unknown",
                    "table_count": table_count,
                }
            else:
                # PostgreSQL
                result = db.execute(text("SELECT version()"))
                version = result.scalar()
                result = db.execute(text("""
                    SELECT COUNT(*) 
                    FROM information_schema.tables 
                    WHERE table_schema = 'public'
                """))
                table_count = result.scalar()
                return {
                    "status": "success",
                    "version": version.split(',')[0] if version else "Unknown",
                    "table_count": table_count,
                }
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
            }
    
    @staticmethod
    def complete_setup(
        db: Session,
        admin_email: str,
        admin_password: str,
        organization_name: str = "Default Organization",
        smtp_host: Optional[str] = None,
        smtp_port: Optional[int] = None,
        smtp_user: Optional[str] = None,
        smtp_password: Optional[str] = None,
    ) -> dict:
        """Complete setup wizard"""
        try:
            # Check if setup is already complete
            if SetupWizard.is_setup_complete(db):
                return {
                    "status": "error",
                    "error": "Setup is already complete. Please reset setup first.",
                }
            
            # Delete any existing users to ensure clean setup
            db.query(models.UserOrganization).delete()
            db.query(models.User).delete()
            db.query(models.Organization).delete()
            db.query(models.Node).delete()
            db.commit()
            
            # Create admin user
            admin_user = SetupWizard.create_admin_user(db, admin_email, admin_password)

            # Create default organization
            org = SetupWizard.create_default_organization(db, organization_name)

            # Link admin to organization
            user_org = models.UserOrganization(
                user_id=admin_user.id,
                organization_id=org.id,
                role="admin",
            )
            db.add(user_org)

            # Create default node
            import secrets
            node = models.Node(
                name="Default Node",
                api_key=secrets.token_urlsafe(32),
            )
            db.add(node)

            db.commit()

            return {
                "status": "success",
                "message": "Setup completed successfully",
                "admin_user_id": admin_user.id,
                "organization_id": org.id,
                "node_id": node.id,
            }
        except ValueError as e:
            db.rollback()
            return {
                "status": "error",
                "error": str(e),
            }
        except Exception as e:
            db.rollback()
            return {
                "status": "error",
                "error": f"Setup failed: {str(e)}",
            }

