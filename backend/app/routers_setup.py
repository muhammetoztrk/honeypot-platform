"""Setup Wizard API Routes"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr
from typing import Optional
from .database import get_db
from . import models
from .setup import SetupWizard

router = APIRouter()


class SetupCheckResponse(BaseModel):
    setup_complete: bool


class SetupCompleteRequest(BaseModel):
    admin_email: EmailStr
    admin_password: str
    organization_name: str = "Default Organization"
    smtp_host: Optional[str] = None
    smtp_port: Optional[int] = None
    smtp_user: Optional[str] = None
    smtp_password: Optional[str] = None


class SetupCompleteResponse(BaseModel):
    status: str
    message: str
    admin_user_id: int = None
    organization_id: int = None
    node_id: int = None
    error: str = None


@router.get("/setup/check", response_model=SetupCheckResponse)
def check_setup_status(db: Session = Depends(get_db)):
    """Check if setup is complete"""
    return {
        "setup_complete": SetupWizard.is_setup_complete(db),
    }


@router.get("/setup/database/test")
def test_database(db: Session = Depends(get_db)):
    """Test database connection"""
    return SetupWizard.test_database_connection(db)


@router.get("/setup/database/info")
def get_database_info(db: Session = Depends(get_db)):
    """Get database information"""
    return SetupWizard.get_database_info(db)


@router.post("/setup/reset")
def reset_setup(db: Session = Depends(get_db)):
    """Reset setup - Delete all users and organizations"""
    try:
        # Delete all users
        db.query(models.User).delete()
        # Delete all organizations
        db.query(models.Organization).delete()
        # Delete all user-organization relationships
        db.query(models.UserOrganization).delete()
        # Delete all nodes
        db.query(models.Node).delete()
        db.commit()
        return {"status": "success", "message": "Setup reset successfully"}
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Reset failed: {str(e)}",
        )


@router.post("/setup/complete", response_model=SetupCompleteResponse)
def complete_setup(
    request: SetupCompleteRequest,
    db: Session = Depends(get_db),
):
    """Complete setup wizard"""
    # Check if setup is already complete
    if SetupWizard.is_setup_complete(db):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Setup is already complete",
        )
    
    # Validate password
    if len(request.admin_password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 8 characters",
        )
    
    # Complete setup
    try:
        result = SetupWizard.complete_setup(
            db=db,
            admin_email=request.admin_email,
            admin_password=request.admin_password,
            organization_name=request.organization_name or "Default Organization",
            smtp_host=request.smtp_host if request.smtp_host else None,
            smtp_port=request.smtp_port if request.smtp_port else None,
            smtp_user=request.smtp_user if request.smtp_user else None,
            smtp_password=request.smtp_password if request.smtp_password else None,
        )
        
        if result["status"] == "error":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result.get("error", "Setup failed"),
            )
        
        return result
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Setup failed: {str(e)}",
        )

