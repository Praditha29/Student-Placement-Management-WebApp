#Student Placement Management System 
from fastapi import FastAPI, Request, Form, Depends, Response, File, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from sqlalchemy import create_engine, String, select, Float
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, Session
import jwt
import bcrypt
from datetime import datetime, timedelta, timezone
import os
import shutil
from typing import Optional

# ==========================================
# 1. SECURITY & JWT CONFIGURATION
# ==========================================
SECRET_KEY = "my_super_secret_key_for_development" # In production, keep this safe!
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Directory for uploaded images
UPLOAD_DIR = "static/uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# We use bcrypt directly to avoid compatibility issues with passlib on newer Python versions
def verify_password(plain_password, hashed_password):
    # Truncate to 72 bytes to match bcrypt algorithm limit and avoid ValueError
    return bcrypt.checkpw(plain_password.encode('utf-8')[:72], hashed_password.encode('utf-8'))

def get_password_hash(password):
    # Truncate to 72 bytes to match bcrypt algorithm limit and avoid ValueError
    return bcrypt.hashpw(password.encode('utf-8')[:72], bcrypt.gensalt()).decode('utf-8')

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# ==========================================
# 2. DATABASE SETUP
# ==========================================
engine = create_engine("sqlite:///final_app.db", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(30))
    email: Mapped[str] = mapped_column(String(50), unique=True)
    hashed_password: Mapped[str] = mapped_column(String(100))
    role: Mapped[str] = mapped_column(String(20), default="user") # "user" or "admin"

class Student(Base):
    __tablename__ = "students"

    id: Mapped[int] = mapped_column(primary_key=True)

    name: Mapped[str] = mapped_column(String(50))
    email: Mapped[str] = mapped_column(String(50), unique=True)

    department: Mapped[str] = mapped_column(String(50))
    semester: Mapped[int]

    cgpa: Mapped[float] = mapped_column(Float)

    attendance_percentage: Mapped[float] = mapped_column(Float)

    placement_status: Mapped[str] = mapped_column(String(30))

class Assessment(Base):
    __tablename__ = "assessments"

    id: Mapped[int] = mapped_column(primary_key=True)

    title: Mapped[str] = mapped_column(String(100))
    subject: Mapped[str] = mapped_column(String(100))

    total_marks: Mapped[int]
    obtained_marks: Mapped[int]

    student_id: Mapped[int]

class Attendance(Base):
    __tablename__ = "attendance"

    id: Mapped[int] = mapped_column(primary_key=True)

    student_id: Mapped[int]

    date: Mapped[str] = mapped_column(String(20))

    status: Mapped[str] = mapped_column(String(10))

class PlacementDrive(Base):
    __tablename__ = "placement_drives"

    id: Mapped[int] = mapped_column(primary_key=True)

    company_name: Mapped[str] = mapped_column(String(100))

    role: Mapped[str] = mapped_column(String(100))

    package: Mapped[float] = mapped_column(Float)

    drive_date: Mapped[str] = mapped_column(String(20))

    eligibility_cgpa: Mapped[float] = mapped_column(Float)

class InterviewFeedback(Base):
    __tablename__ = "interview_feedback"

    id: Mapped[int] = mapped_column(primary_key=True)

    student_id: Mapped[int]

    company_name: Mapped[str] = mapped_column(String(100))

    technical_feedback: Mapped[str] = mapped_column(String(300))

    hr_feedback: Mapped[str] = mapped_column(String(300))

    result: Mapped[str] = mapped_column(String(30))

Base.metadata.create_all(bind=engine)

# ==========================================
# 3. FASTAPI SETUP & DEPENDENCIES
# ==========================================
app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="Frontend") 

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# The Guard: This function checks the user's cookies for a valid JWT
def get_current_user(request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get("access_token")
    if not token:
        return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            return None
    except jwt.InvalidTokenError:
        return None
    
    # If the token is valid, find the user in the database
    user = db.scalars(select(User).where(User.email == email)).first()
    return user

# ==========================================
# 4. AUTHENTICATION ROUTES (Login/Signup)
# ==========================================

@app.get("/signup", response_class=HTMLResponse)
def signup_page(request: Request):
    return templates.TemplateResponse(request=request, name="signup.html")

@app.post("/signup")
def signup_post(
    request: Request,
    name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    role: str = Form(...),
    db: Session = Depends(get_db)):

    existing_user = db.scalars(select(User).where(User.email == email)).first()
    if existing_user:
        return templates.TemplateResponse(request=request, name="signup.html", context={"error": "Email already registered."})
    
    new_user = User(
    name=name,
    email=email,
    hashed_password=get_password_hash(password),
    role=role)

    db.add(new_user)
    db.commit()
    
    access_token = create_access_token(
    data={
        "sub": new_user.email,
        "role": new_user.role
    }
)
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(
    key="access_token",
    value=access_token,
    httponly=True,
    secure=False,      # True if using HTTPS
    samesite="lax"
)
    return response

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(request=request, name="login.html")

@app.post("/login")
def login_post(request: Request, email: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = db.scalars(select(User).where(User.email == email)).first()
    if not user or not verify_password(password, user.hashed_password):
        return templates.TemplateResponse(request=request, name="login.html", context={"error": "Invalid email or password."})
    
    access_token = create_access_token(
    data={
        "sub": user.email,
        "role": user.role
    }
)
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(
    key="access_token",
    value=access_token,
    httponly=True,
    secure=False,      # True if using HTTPS
    samesite="lax"
)
    return response

@app.get("/logout")
def logout():
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie("access_token")
    return response



# ==========================================
# 5. Using CRUD
# ==========================================

@app.get("/")
def home(current_user: User = Depends(get_current_user)):
    if not current_user:
        return RedirectResponse("/login", status_code=303)

    if current_user.role == "admin":
        return RedirectResponse("/admin")

    elif current_user.role == "trainer":
        return RedirectResponse("/trainer")

    return RedirectResponse("/student")

@app.get("/admin")
def admin_dashboard(
        request: Request,
        current_user: User = Depends(get_current_user)
):

    if not current_user or current_user.role != "admin":
        return RedirectResponse("/login", status_code=303)

    return templates.TemplateResponse(
        request=request,
        name="admin.html",
        context={"current_user": current_user}
    )

@app.get("/trainer")
def trainer_dashboard(
        request: Request,
        current_user: User = Depends(get_current_user)
):

    if not current_user or current_user.role != "trainer":
        return RedirectResponse("/login", status_code=303)

    return templates.TemplateResponse(
        request=request,
        name="trainer.html",
        context={"current_user": current_user}
    )

@app.get("/student")
def student_dashboard(
        request: Request,
        current_user: User = Depends(get_current_user)
):

    if not current_user or current_user.role != "student":
        return RedirectResponse("/login", status_code=303)

    return templates.TemplateResponse(
        request=request,
        name="student.html",
        context={"current_user": current_user}
    )

# Student Creation Route 
@app.post("/student/create")
def create_student(
        name: str = Form(...),
        email: str = Form(...),
        department: str = Form(...),
        semester: int = Form(...),
        cgpa: float = Form(...),
        attendance_percentage: float = Form(...),
        placement_status: str = Form(...),
        db: Session = Depends(get_db)
):

    student = Student(
        name=name,
        email=email,
        department=department,
        semester=semester,
        cgpa=cgpa,
        attendance_percentage=attendance_percentage,
        placement_status=placement_status
    )

    db.add(student)
    db.commit()

    return RedirectResponse("/admin", status_code=303)

# Placement CRUD
@app.post("/drive/create")
def create_drive(
        company_name: str = Form(...),
        role: str = Form(...),
        package: float = Form(...),
        drive_date: str = Form(...),
        eligibility_cgpa: float = Form(...),
        db: Session = Depends(get_db)
):

    drive = PlacementDrive(
        company_name=company_name,
        role=role,
        package=package,
        drive_date=drive_date,
        eligibility_cgpa=eligibility_cgpa
    )

    db.add(drive)
    db.commit()

    return RedirectResponse("/admin", status_code=303)

#Attendance CRUD
@app.post("/attendance/create")
def create_attendance(
        student_id: int = Form(...),
        date: str = Form(...),
        status: str = Form(...),
        db: Session = Depends(get_db)
):

    attendance = Attendance(
        student_id=student_id,
        date=date,
        status=status
    )

    db.add(attendance)
    db.commit()

    return RedirectResponse("/trainer", status_code=303)

#Assessment CRUD
@app.post("/assessment/create")
def create_assessment(
        title: str = Form(...),
        subject: str = Form(...),
        total_marks: int = Form(...),
        obtained_marks: int = Form(...),
        student_id: int = Form(...),
        db: Session = Depends(get_db)
):

    assessment = Assessment(
        title=title,
        subject=subject,
        total_marks=total_marks,
        obtained_marks=obtained_marks,
        student_id=student_id
    )

    db.add(assessment)
    db.commit()

    return RedirectResponse("/trainer", status_code=303)


# =====================
# STUDENT PAGES
# =====================

@app.get("/student/assessments", response_class=HTMLResponse)
def assessment_page(
    request: Request,
    current_user: User = Depends(get_current_user)
):
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    return templates.TemplateResponse(
        request=request,
        name="assessment.html",
        context={"current_user": current_user}
    )


@app.get("/student/attendance", response_class=HTMLResponse)
def attendance_page(
    request: Request,
    current_user: User = Depends(get_current_user)
):
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    return templates.TemplateResponse(
        request=request,
        name="attendance.html",
        context={"current_user": current_user}
    )

@app.get("/student/assignment", response_class=HTMLResponse)
def assignment_page(
    request: Request,
    current_user: User = Depends(get_current_user)
):
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    return templates.TemplateResponse(
        request=request,
        name="assignment.html",
        context={"current_user": current_user}
    )

@app.get("/student/feedback", response_class=HTMLResponse)
def feedback_page(
    request: Request,
    current_user: User = Depends(get_current_user)
):
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    return templates.TemplateResponse(
        request=request,
        name="feedback.html",
        context={"current_user": current_user}
    )


@app.get("/student/drives", response_class=HTMLResponse)
def drive_page(
    request: Request,
    current_user: User = Depends(get_current_user)
):
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    return templates.TemplateResponse(
        request=request,
        name="placement.html",
        context={"current_user": current_user}
    )

@app.get("/student/profile", response_class=HTMLResponse)
def profile(
    request: Request,
    current_user: User = Depends(get_current_user)
):
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    return templates.TemplateResponse(
        request=request,
        name="student_profile.html",
        context={"current_user": current_user}
    )



# @app.get("/", response_class=HTMLResponse)
# def home_page(request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
#     if not current_user:
#         return RedirectResponse(url="/login", status_code=303)
        
#     products = db.scalars(select(Product)).all()
#     return templates.TemplateResponse(
#         request=request, 
#         name="index.html", 
#         context={"products": products, "current_user": current_user}
#     )

# @app.get("/create", response_class=HTMLResponse)
# def create_page(request: Request, current_user: User = Depends(get_current_user)):
#     if not current_user: return RedirectResponse(url="/login", status_code=303)
#     return templates.TemplateResponse(request=request, name="create.html")

# @app.post("/create")
# async def create_product(
#     name: str = Form(...), 
#     description: str = Form(...), 
#     price: str = Form(...), 
#     image: Optional[UploadFile] = File(None),
#     db: Session = Depends(get_db),
#     current_user: User = Depends(get_current_user)
# ):
#     if not current_user: return RedirectResponse(url="/login", status_code=303)
    
#     image_path = None
#     if image and image.filename:
#         file_extension = os.path.splitext(image.filename)[1]
#         unique_filename = f"{datetime.now().timestamp()}{file_extension}"
#         image_path = f"uploads/{unique_filename}"
#         with open(os.path.join(UPLOAD_DIR, unique_filename), "wb") as buffer:
#             shutil.copyfileobj(image.file, buffer)

#     new_product = Product(name=name, description=description, price=price, image_path=image_path)
#     db.add(new_product)
#     db.commit()
#     return RedirectResponse(url="/", status_code=303)

# @app.get("/update/{product_id}", response_class=HTMLResponse)
# def update_page(request: Request, product_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
#     if not current_user: return RedirectResponse(url="/login", status_code=303)
#     product = db.get(Product, product_id)
#     return templates.TemplateResponse(request=request, name="update.html", context={"product": product})

# @app.post("/update/{product_id}")
# async def update_product(
#     product_id: int, 
#     name: str = Form(...), 
#     description: str = Form(...), 
#     price: str = Form(...), 
#     image: Optional[UploadFile] = File(None),
#     db: Session = Depends(get_db),
#     current_user: User = Depends(get_current_user)
# ):
#     if not current_user: return RedirectResponse(url="/login", status_code=303)
    
#     product = db.get(Product, product_id)
#     if product:
#         product.name = name
#         product.description = description
#         product.price = price
        
#         if image and image.filename:
#             # Delete old image if it exists
#             if product.image_path:
#                 old_path = os.path.join("static", product.image_path)
#                 if os.path.exists(old_path):
#                     os.remove(old_path)
            
#             file_extension = os.path.splitext(image.filename)[1]
#             unique_filename = f"{datetime.now().timestamp()}{file_extension}"
#             product.image_path = f"uploads/{unique_filename}"
#             with open(os.path.join(UPLOAD_DIR, unique_filename), "wb") as buffer:
#                 shutil.copyfileobj(image.file, buffer)
                
#         db.commit()
#     return RedirectResponse(url="/", status_code=303)

# @app.get("/delete/{product_id}")
# def delete_product(product_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
#     if not current_user: return RedirectResponse(url="/login", status_code=303)
#     product = db.get(Product, product_id)
#     if product:
#         if product.image_path:
#             old_path = os.path.join("static", product.image_path)
#             if os.path.exists(old_path):
#                 os.remove(old_path)
#         db.delete(product)
#         db.commit()
#     return RedirectResponse(url="/", status_code=303)