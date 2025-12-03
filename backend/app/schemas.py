from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr


class UserCreate(BaseModel):
  email: EmailStr
  password: str


class UserRead(BaseModel):
  id: int
  email: EmailStr
  role: str

  class Config:
    from_attributes = True


class Token(BaseModel):
  access_token: str
  token_type: str = "bearer"


class NodeCreate(BaseModel):
  name: str


class NodeRead(BaseModel):
  id: int
  name: str
  api_key: str
  last_heartbeat_at: Optional[datetime]

  class Config:
    from_attributes = True


class HoneypotCreate(BaseModel):
  node_id: int
  template_id: int
  name: str
  listen_ip: str = "0.0.0.0"
  listen_port: int


class HoneypotRead(BaseModel):
  id: int
  node_id: int
  template_id: int
  name: str
  listen_ip: str
  listen_port: int
  status: str

  class Config:
    from_attributes = True


class SessionRead(BaseModel):
  id: int
  honeypot_id: int
  src_ip: str
  src_port: int
  protocol: str
  started_at: datetime
  ended_at: Optional[datetime]
  score: int

  class Config:
    from_attributes = True


class EventCreate(BaseModel):
  session_id: int
  honeypot_id: int
  src_ip: str
  dst_port: int
  event_type: str
  payload: dict


class EventRead(BaseModel):
  id: int
  session_id: int
  honeypot_id: int
  ts: datetime
  src_ip: str
  dst_port: int
  event_type: str
  payload: dict

  class Config:
    from_attributes = True


class IOCRead(BaseModel):
  id: int
  ioc_type: str
  value: str
  first_seen: datetime
  last_seen: datetime
  seen_count: int
  score: int

  class Config:
    from_attributes = True


class AgentHeartbeat(BaseModel):
  api_key: str


class AgentEventSubmit(BaseModel):
  api_key: str
  honeypot_id: int
  src_ip: str
  src_port: int
  protocol: str = "tcp"
  event_type: str
  timestamp: Optional[datetime] = None
  payload: dict


class AlertRead(BaseModel):
  id: int
  severity: str
  title: str
  message: str
  event_id: Optional[int]
  ioc_id: Optional[int]
  read: bool
  created_at: datetime

  class Config:
    from_attributes = True


class HoneypotTemplateRead(BaseModel):
  id: int
  name: str
  type: str
  default_config: dict

  class Config:
    from_attributes = True


class BlockedIPRead(BaseModel):
  id: int
  ip: str
  reason: str
  blocked_at: datetime
  blocked_by: Optional[int]

  class Config:
    from_attributes = True


class IOCEnrichmentRead(BaseModel):
  id: int
  ioc_id: int
  source: str
  data: dict
  enriched_at: datetime

  class Config:
    from_attributes = True


class AlertRuleRead(BaseModel):
  id: int
  name: str
  enabled: bool
  conditions: dict
  actions: dict
  created_at: datetime

  class Config:
    from_attributes = True


class ScheduledReportRead(BaseModel):
  id: int
  name: str
  enabled: bool
  schedule_type: str
  format: str
  recipients: list
  last_run: Optional[datetime]
  next_run: Optional[datetime]
  created_at: datetime

  class Config:
    from_attributes = True


class WebhookConfigRead(BaseModel):
  id: int
  name: str
  url: str
  type: str
  enabled: bool
  events: list
  created_at: datetime

  class Config:
    from_attributes = True


class BackupRead(BaseModel):
  id: int
  filename: str
  size_bytes: int
  backup_type: str
  created_at: datetime

  class Config:
    from_attributes = True


class IncidentRead(BaseModel):
  id: int
  title: str
  description: Optional[str]
  status: str
  severity: str
  assigned_to: Optional[int]
  created_at: datetime

  class Config:
    from_attributes = True


class PlaybookRead(BaseModel):
  id: int
  name: str
  description: Optional[str]
  enabled: bool
  trigger_conditions: dict
  steps: list
  created_at: datetime

  class Config:
    from_attributes = True


class TagRead(BaseModel):
  id: int
  name: str
  color: str
  created_at: datetime

  class Config:
    from_attributes = True


class OrganizationRead(BaseModel):
  id: int
  name: str
  created_at: datetime

  class Config:
    from_attributes = True



