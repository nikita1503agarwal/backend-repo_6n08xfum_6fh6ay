import os
import base64
import asyncio
import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Optional

from fastapi import FastAPI, HTTPException, Depends, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from pydantic import BaseModel

from database import db, create_document, get_documents
from schemas import (
    AuthUser,
    MarketItem,
    Club,
    Feedback,
    Question,
    Answer,
    Notification,
    LocationPhoto,
    Token,
    GeoCheckRequest,
    GeoCheckResponse,
)

app = FastAPI(title="CollegeMate API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------
# Helpers: Auth & Utilities
# ---------------------------

def hash_password(password: str, salt: Optional[str] = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}${digest}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt, digest = stored.split("$")
    except ValueError:
        return False
    candidate = hashlib.sha256((salt + password).encode()).hexdigest()
    return secrets.compare_digest(candidate, digest)


def issue_token(user_id: str, ttl_hours: int = 72) -> str:
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(hours=ttl_hours)
    db["session"].insert_one({
        "user_id": user_id,
        "token": token,
        "expires_at": expires_at,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    })
    return token


async def get_current_user(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    token = authorization.split(" ")[-1]
    session = db["session"].find_one({"token": token})
    if not session:
        raise HTTPException(status_code=401, detail="Invalid token")
    if session.get("expires_at") and session["expires_at"] < datetime.now(timezone.utc):
        db["session"].delete_one({"_id": session["_id"]})
        raise HTTPException(status_code=401, detail="Token expired")
    user = db["authuser"].find_one({"_id": session["user_id"]})
    if not user:
        # Support for string ids stored in session
        user = db["authuser"].find_one({"_id": session.get("user_id")})
    if not user:
        # Try match by hex string id in string form
        try:
            from bson import ObjectId
            user = db["authuser"].find_one({"_id": ObjectId(session["user_id"])})
        except Exception:
            user = None
    if not user:
        raise HTTPException(status_code=401, detail="User not found for token")
    return user


# ---------------------------
# Health & Test
# ---------------------------
@app.get("/")
def root():
    return {"message": "CollegeMate API running"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Connected & Working"
            response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
            response["database_name"] = db.name
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:20]
            except Exception as e:
                response["database"] = f"⚠️ Connected but error listing collections: {str(e)[:80]}"
        else:
            response["database"] = "⚠️ Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:120]}"
    return response


# ---------------------------
# Auth Endpoints
# ---------------------------
class RegisterRequest(BaseModel):
    name: str
    email: str
    password: str


@app.post("/auth/register", response_model=Token)
def register(body: RegisterRequest):
    existing = db["authuser"].find_one({"email": body.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user = AuthUser(
        name=body.name,
        email=body.email,
        password_hash=hash_password(body.password),
    )
    user_id = create_document("authuser", user)
    token = issue_token(user_id)
    return Token(access_token=token)


class LoginRequest(BaseModel):
    email: str
    password: str


@app.post("/auth/login", response_model=Token)
def login(body: LoginRequest):
    doc = db["authuser"].find_one({"email": body.email})
    if not doc:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not verify_password(body.password, doc.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = issue_token(str(doc.get("_id")))
    return Token(access_token=token)


@app.get("/auth/me")
def me(user: Dict[str, Any] = Depends(get_current_user)):
    # Do not expose password hash
    user.pop("password_hash", None)
    # Ensure id is string
    if "_id" in user:
        user["id"] = str(user.pop("_id"))
    return user


# ---------------------------
# Marketplace CRUD
# ---------------------------
@app.post("/market/items")
def create_item(item: MarketItem, user: Dict[str, Any] = Depends(get_current_user)):
    if item.owner_id != str(user.get("_id", user.get("id"))):
        # Enforce owner is current user
        item.owner_id = str(user.get("_id", user.get("id")))
    item_id = create_document("marketitem", item)
    return {"id": item_id}


@app.get("/market/items")
def list_items(category: Optional[str] = None, include_sold: bool = False):
    filt: Dict[str, Any] = {}
    if category:
        filt["category"] = category
    if not include_sold:
        filt["is_sold"] = False
    items = get_documents("marketitem", filt)
    for it in items:
        it["id"] = str(it.pop("_id"))
    return items


@app.patch("/market/items/{item_id}/sold")
def mark_sold(item_id: str, user: Dict[str, Any] = Depends(get_current_user)):
    doc = db["marketitem"].find_one({"_id": db.client.get_default_database().codec_options.document_class().get("_id", item_id)})
    # Fallback simple update by string id
    try:
        from bson import ObjectId
        oid = ObjectId(item_id)
        doc = db["marketitem"].find_one({"_id": oid})
    except Exception:
        doc = db["marketitem"].find_one({"_id": item_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Item not found")
    if str(doc.get("owner_id")) != str(user.get("_id", user.get("id"))):
        raise HTTPException(status_code=403, detail="Not item owner")
    db["marketitem"].update_one({"_id": doc["_id"]}, {"$set": {"is_sold": True, "updated_at": datetime.now(timezone.utc)}})
    return {"status": "ok"}


@app.delete("/market/items/{item_id}")
def delete_item(item_id: str, user: Dict[str, Any] = Depends(get_current_user)):
    try:
        from bson import ObjectId
        filt = {"_id": ObjectId(item_id)}
    except Exception:
        filt = {"_id": item_id}
    doc = db["marketitem"].find_one(filt)
    if not doc:
        raise HTTPException(status_code=404, detail="Item not found")
    if str(doc.get("owner_id")) != str(user.get("_id", user.get("id"))):
        raise HTTPException(status_code=403, detail="Not item owner")
    db["marketitem"].delete_one(filt)
    return {"status": "deleted"}


# ---------------------------
# Clubs
# ---------------------------
@app.post("/clubs")
def create_club(club: Club, user: Dict[str, Any] = Depends(get_current_user)):
    club.created_by = str(user.get("_id", user.get("id")))
    if not club.member_ids:
        club.member_ids = [club.created_by]
    club_id = create_document("club", club)
    return {"id": club_id}


@app.get("/clubs")
def list_clubs():
    clubs = get_documents("club")
    for c in clubs:
        c["id"] = str(c.pop("_id"))
    return clubs


@app.post("/clubs/{club_id}/join")
def join_club(club_id: str, user: Dict[str, Any] = Depends(get_current_user)):
    try:
        from bson import ObjectId
        filt = {"_id": ObjectId(club_id)}
    except Exception:
        filt = {"_id": club_id}
    club = db["club"].find_one(filt)
    if not club:
        raise HTTPException(status_code=404, detail="Club not found")
    uid = str(user.get("_id", user.get("id")))
    db["club"].update_one(filt, {"$addToSet": {"member_ids": uid}, "$set": {"updated_at": datetime.now(timezone.utc)}})
    return {"status": "joined"}


@app.post("/clubs/{club_id}/leave")
def leave_club(club_id: str, user: Dict[str, Any] = Depends(get_current_user)):
    try:
        from bson import ObjectId
        filt = {"_id": ObjectId(club_id)}
    except Exception:
        filt = {"_id": club_id}
    uid = str(user.get("_id", user.get("id")))
    db["club"].update_one(filt, {"$pull": {"member_ids": uid}, "$set": {"updated_at": datetime.now(timezone.utc)}})
    return {"status": "left"}


# ---------------------------
# Feedback (anonymous by default)
# ---------------------------
@app.post("/feedback")
def submit_feedback(fb: Feedback, user: Dict[str, Any] = Depends(get_current_user)):
    if not fb.anonymous:
        fb.user_id = str(user.get("_id", user.get("id")))
    feedback_id = create_document("feedback", fb)
    return {"id": feedback_id}


@app.get("/feedback")
def list_feedback():
    items = get_documents("feedback")
    for it in items:
        it["id"] = str(it.pop("_id"))
        if it.get("anonymous", True):
            it.pop("user_id", None)
    return items


# ---------------------------
# Q&A with reputation
# ---------------------------
@app.post("/qa/questions")
def create_question(q: Question, user: Dict[str, Any] = Depends(get_current_user)):
    q.author_id = str(user.get("_id", user.get("id")))
    qid = create_document("question", q)
    return {"id": qid}


@app.get("/qa/questions")
def list_questions(tag: Optional[str] = None):
    filt = {"tags": tag} if tag else {}
    qs = get_documents("question", filt)
    for x in qs:
        x["id"] = str(x.pop("_id"))
    return qs


@app.post("/qa/questions/{qid}/upvote")
def upvote_question(qid: str, user: Dict[str, Any] = Depends(get_current_user)):
    try:
        from bson import ObjectId
        filt = {"_id": ObjectId(qid)}
    except Exception:
        filt = {"_id": qid}
    doc = db["question"].find_one(filt)
    if not doc:
        raise HTTPException(status_code=404, detail="Question not found")
    db["question"].update_one(filt, {"$inc": {"upvotes": 1}, "$set": {"updated_at": datetime.now(timezone.utc)}})
    # Increase reputation of the author
    author_id = doc.get("author_id")
    if author_id:
        try:
            from bson import ObjectId
            afilt = {"_id": ObjectId(author_id)}
        except Exception:
            afilt = {"_id": author_id}
        db["authuser"].update_one(afilt, {"$inc": {"reputation": 5}})
    return {"status": "ok"}


@app.post("/qa/answers")
def create_answer(ans: Answer, user: Dict[str, Any] = Depends(get_current_user)):
    ans.author_id = str(user.get("_id", user.get("id")))
    aid = create_document("answer", ans)
    return {"id": aid}


@app.get("/qa/answers/{qid}")
def list_answers(qid: str):
    answers = get_documents("answer", {"question_id": qid})
    for a in answers:
        a["id"] = str(a.pop("_id"))
    return answers


@app.post("/qa/answers/{aid}/upvote")
def upvote_answer(aid: str, user: Dict[str, Any] = Depends(get_current_user)):
    try:
        from bson import ObjectId
        filt = {"_id": ObjectId(aid)}
    except Exception:
        filt = {"_id": aid}
    doc = db["answer"].find_one(filt)
    if not doc:
        raise HTTPException(status_code=404, detail="Answer not found")
    db["answer"].update_one(filt, {"$inc": {"upvotes": 1}, "$set": {"updated_at": datetime.now(timezone.utc)}})
    # Reputation boost for author
    author_id = doc.get("author_id")
    if author_id:
        try:
            from bson import ObjectId
            afilt = {"_id": ObjectId(author_id)}
        except Exception:
            afilt = {"_id": author_id}
        db["authuser"].update_one(afilt, {"$inc": {"reputation": 10}})
    return {"status": "ok"}


# ---------------------------
# Geolocation and Photos
# ---------------------------
# PDA College approximate center (Kalaburagi, Karnataka) and 800m radius
CAMPUS_CENTER = (17.3295, 76.8340)
CAMPUS_RADIUS_M = 800.0


def haversine_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    from math import radians, sin, cos, sqrt, atan2
    R = 6371000.0
    dlat = radians(lat2 - lat1)
    dlon = radians(lon2 - lon1)
    a = sin(dlat/2)**2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon/2)**2
    c = 2 * atan2(sqrt(a), sqrt(1 - a))
    return R * c


@app.post("/geo/check", response_model=GeoCheckResponse)
def geo_check(body: GeoCheckRequest):
    dist = haversine_m(body.lat, body.lng, CAMPUS_CENTER[0], CAMPUS_CENTER[1])
    inside = dist <= CAMPUS_RADIUS_M
    msg = "Inside campus" if inside else f"Outside campus by {int(dist - CAMPUS_RADIUS_M)} m"
    return GeoCheckResponse(inside=inside, distance_m=dist, message=msg)


@app.post("/geo/photos")
def upload_location_photo(p: LocationPhoto, user: Dict[str, Any] = Depends(get_current_user)):
    # Validate base64
    try:
        base64.b64decode(p.image_b64.split(",")[-1], validate=True)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 image")
    p.uploaded_by = str(user.get("_id", user.get("id")))
    pid = create_document("locationphoto", p)
    return {"id": pid}


@app.get("/geo/photos")
def list_location_photos(lat: Optional[float] = None, lng: Optional[float] = None, radius_m: float = 500.0):
    filt: Dict[str, Any] = {}
    photos = get_documents("locationphoto", filt)
    out: List[Dict[str, Any]] = []
    for ph in photos:
        ph["id"] = str(ph.pop("_id"))
        # If lat/lng provided, filter by distance
        if lat is not None and lng is not None:
            d = haversine_m(lat, lng, ph.get("lat"), ph.get("lng"))
            if d <= radius_m:
                out.append(ph)
        else:
            out.append(ph)
    return out


# ---------------------------
# Real-time Notifications (SSE)
# ---------------------------
subscribers: List[asyncio.Queue] = []


async def event_generator(queue: asyncio.Queue):
    try:
        while True:
            data = await queue.get()
            yield f"data: {data}\n\n"
    except asyncio.CancelledError:
        return


@app.get("/events")
async def sse_events(request: Request):
    queue: asyncio.Queue = asyncio.Queue()
    subscribers.append(queue)

    async def cleanup():
        if queue in subscribers:
            subscribers.remove(queue)

    async def stream():
        try:
            async for event in event_generator(queue):
                yield event
                if await request.is_disconnected():
                    break
        finally:
            await cleanup()

    return StreamingResponse(stream(), media_type="text/event-stream")


@app.post("/notifications")
def create_notification(n: Notification, user: Dict[str, Any] = Depends(get_current_user)):
    n.created_by = str(user.get("_id", user.get("id")))
    nid = create_document("notification", n)
    # Broadcast
    payload = {
        "id": nid,
        "title": n.title,
        "body": n.body,
        "type": n.type,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    for q in list(subscribers):
        try:
            q.put_nowait(json_dumps(payload))
        except Exception:
            continue
    return {"id": nid}


@app.get("/notifications")
def list_notifications(limit: int = 50):
    items = get_documents("notification", limit=limit)
    for it in items:
        it["id"] = str(it.pop("_id"))
    return items


# Small helper to avoid importing orjson
def json_dumps(obj: Any) -> str:
    import json
    return json.dumps(obj, default=str)


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
