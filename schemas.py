"""
Database Schemas for CollegeMate

Each Pydantic model maps to a MongoDB collection using the lowercased class name.
Example: User -> "user" collection
"""
from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List
from datetime import datetime

class AuthUser(BaseModel):
    name: str = Field(..., min_length=2, max_length=80)
    email: EmailStr
    password_hash: str
    avatar_url: Optional[str] = None
    role: str = Field("student", description="student|admin|moderator")
    reputation: int = 0
    is_active: bool = True

class MarketItem(BaseModel):
    title: str
    description: Optional[str] = None
    price: float = Field(..., ge=0)
    category: str
    owner_id: str
    photos: List[str] = []  # base64 strings or URLs
    is_sold: bool = False

class Club(BaseModel):
    name: str
    description: Optional[str] = None
    created_by: str
    member_ids: List[str] = []

class Feedback(BaseModel):
    message: str
    category: str = Field("general")
    anonymous: bool = True
    user_id: Optional[str] = None

class Question(BaseModel):
    title: str
    body: str
    tags: List[str] = []
    author_id: str
    upvotes: int = 0

class Answer(BaseModel):
    question_id: str
    body: str
    author_id: str
    upvotes: int = 0

class Notification(BaseModel):
    title: str
    body: str
    type: str = Field("general")
    created_by: Optional[str] = None
    audience: str = Field("all")

class LocationPhoto(BaseModel):
    title: str
    lat: float
    lng: float
    uploaded_by: Optional[str] = None
    image_b64: str

# Utility models for responses
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class GeoCheckRequest(BaseModel):
    lat: float
    lng: float

class GeoCheckResponse(BaseModel):
    inside: bool
    distance_m: float
    message: str
    
