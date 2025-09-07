# main.py
from fastapi import FastAPI, Depends, HTTPException, status, Path
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from sqlmodel import SQLModel, Field, create_engine, Session, select
from passlib.context import CryptContext
from typing import Optional
from datetime import datetime, timedelta
import jwt

# ----- CONFIG -----
JWT_SECRET = "change_this_secret_in_prod"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

DATABASE_URL = "sqlite:///./database.db"

# ----- DB models -----
class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str
    hashed_password: str
    role: str  # 'student' or 'teacher'
    display_name: Optional[str] = None
    phone: Optional[str] = None

class Alert(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    alert_type: str
    message: str
    created_by: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    active: bool = True

class Response(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    alert_id: int
    user_id: int
    status: str  # 'safe' or 'need_help'
    timestamp: datetime = Field(default_factory=datetime.utcnow)

# ----- Setup DB -----
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SQLModel.metadata.create_all(engine)

# ----- Security utilities -----
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=ALGORITHM)
    return encoded_jwt

def decode_token(token: str):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        return payload
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

def get_current_user(token: str = Depends(oauth2_scheme)):
    payload = decode_token(token)
    username = payload.get("sub")
    role = payload.get("role")
    if username is None or role is None:
        raise HTTPException(status_code=401, detail="Invalid token payload")
    with Session(engine) as session:
        user = session.exec(select(User).where(User.username == username)).first()
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user

# ----- App -----
app = FastAPI(title="EduSafe - Backend Prototype")

# ----- Seed demo users (if not exist) -----
def seed_users():
    demo = [
        {"username":"student1","password":"studpass","role":"student","display_name":"Rahul","phone":"9999999001"},
        {"username":"student2","password":"studpass","role":"student","display_name":"Priya","phone":"9999999002"},
        {"username":"teacher1","password":"teachpass","role":"teacher","display_name":"Ms. Kaur","phone":"9999999111"},
    ]
    with Session(engine) as session:
        for u in demo:
            exists = session.exec(select(User).where(User.username == u["username"])).first()
            if not exists:
                user = User(username=u["username"], hashed_password=get_password_hash(u["password"]),
                            role=u["role"], display_name=u["display_name"], phone=u["phone"])
                session.add(user)
        session.commit()

seed_users()

# ----- Auth endpoint -----
@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    with Session(engine) as session:
        user = session.exec(select(User).where(User.username == form_data.username)).first()
        if not user or not verify_password(form_data.password, user.hashed_password):
            raise HTTPException(status_code=400, detail="Incorrect username or password")
        token = create_access_token({"sub": user.username, "role": user.role})
        return {"access_token": token, "token_type": "bearer", "role": user.role}

# ----- Create alert (teacher only) -----
@app.post("/alerts")
def create_alert(alert_type: str, message: str, current_user: User = Depends(get_current_user)):
    if current_user.role != "teacher":
        raise HTTPException(status_code=403, detail="Only teachers can create alerts")
    with Session(engine) as session:
        al = Alert(alert_type=alert_type, message=message, created_by=current_user.username)
        session.add(al); session.commit(); session.refresh(al)
        return {"msg":"alert created","alert":al}

# ----- List alerts (any logged user) -----
@app.get("/alerts")
def list_alerts(current_user: User = Depends(get_current_user)):
    with Session(engine) as session:
        alerts = session.exec(select(Alert).order_by(Alert.created_at.desc())).all()
        return alerts

# ----- Student respond to alert -----
@app.post("/alerts/{alert_id}/respond")
def respond_alert(alert_id: int = Path(..., gt=0), status: str = "safe", current_user: User = Depends(get_current_user)):
    if current_user.role != "student":
        raise HTTPException(status_code=403, detail="Only students can respond to alerts")
    if status not in ("safe","need_help"):
        raise HTTPException(status_code=400, detail="status must be 'safe' or 'need_help'")
    with Session(engine) as session:
        alert = session.get(Alert, alert_id)
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        resp = Response(alert_id=alert_id, user_id=current_user.id, status=status)
        session.add(resp); session.commit(); session.refresh(resp)
        return {"msg":"response recorded","response":resp}

# ----- Dashboard for teacher: summary + recent responses -----
@app.get("/dashboard")
def dashboard(current_user: User = Depends(get_current_user)):
    if current_user.role != "teacher":
        raise HTTPException(status_code=403, detail="Only teachers can view dashboard")
    with Session(engine) as session:
        latest_alert = session.exec(select(Alert).order_by(Alert.created_at.desc())).first()
        if not latest_alert:
            return {"msg":"no alerts yet","summary":{}}
        total_students = session.exec(select(User).where(User.role == "student")).all()
        responses = session.exec(select(Response).where(Response.alert_id == latest_alert.id)).all()
        safe_count = sum(1 for r in responses if r.status=="safe")
        help_count = sum(1 for r in responses if r.status=="need_help")
        return {
            "alert": latest_alert,
            "summary": {
                "total_students": len(total_students),
                "safe_count": safe_count,
                "need_help_count": help_count,
                "responses": [ {"user_id":r.user_id, "status":r.status, "time":r.timestamp.isoformat()} for r in responses ]
            }
        }

# ----- Simple endpoint to add test students (teacher only) -----
@app.post("/students/add")
def add_student(username: str, password: str = "studpass", display_name: str = None, phone: str = None, current_user: User = Depends(get_current_user)):
    if current_user.role != "teacher":
        raise HTTPException(status_code=403, detail="Only teachers can add students")
    with Session(engine) as session:
        exists = session.exec(select(User).where(User.username==username)).first()
        if exists:
            raise HTTPException(status_code=400, detail="username exists")
        user = User(username=username, hashed_password=get_password_hash(password), role="student", display_name=display_name, phone=phone)
        session.add(user); session.commit(); session.refresh(user)
        return {"msg":"student added","user":user}
