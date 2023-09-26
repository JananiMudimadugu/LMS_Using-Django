from fastapi import FastAPI, HTTPException, status, Depends
from datetime import date, datetime,timedelta
from typing import Annotated
from pydantic import BaseModel
from database import SessionLocal
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from jose import jwt, JWTError
from passlib.context import CryptContext
import models
from enum import Enum
from typing import  List


SECRET_KEY = "6846c16fbe5983e6ef52b53bec771e302c6418abd21f911460bb8fa21e0ca4e1"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


db = SessionLocal()


class BookStatusEnum(str, Enum):
    available = "available"
    issued = "issued"

class Admin(BaseModel):
    id : int
    username : str
    email : str
    hashed_password : str
    is_active : bool


class Students(BaseModel):
    s_id : int
    s_name : str
    username : str
    email : str
    hashed_password : str

class Books(BaseModel):
    b_id : int
    title : str
    author : str
    status : str

class StudentBooks(BaseModel):
    s_no : int
    s_id : int
    b_id : int
    date_of_issue : date
    expected_return_date : date
    return_date : date
    penalty : int


class Student_Books_join(BaseModel):
    s_id : int
    b_id : int
    s_name : str
    date_of_issue : date
    title : str
    author : str


class Token(BaseModel):
    access_token : str
    token_type : str

class TokenData(BaseModel):
    username : str | None = None

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI(
    title="Library Management System",
    description="Digital Library"
)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)

def get_admin(db, username: str):
    res = db.query(models.Admin).filter(models.Admin.username == username).first()
    print(res)
    if res is not None:
        return (vars(res))

    get_student(db, username)


def authenticate_admin(db, username: str, password: str):
    admin = get_admin(db, username)
    if not admin:
        return False
    if not verify_password(password, admin["hashed_password"]):
        return False
    return admin

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_admin(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_admin(db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_admin(
    current_user: Annotated[Admin, Depends(get_current_admin)]
):
    # if current_user["disabled"]:
    #     raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

@app.post("/addAdmin", status_code=status.HTTP_201_CREATED, tags=["Admin"])
def add_admin(admin: Admin, current_user : Annotated[Admin, Depends(get_current_active_admin)]):
    new_admin = models.Admin(
        id = admin.id,
        username = admin.username,
        email = admin.email,
        hashed_password = get_password_hash(admin.hashed_password),

    )
    db.add(new_admin)
    db.commit()
    return new_admin

@app.post("/token", response_model=Token, tags=["Admin"])
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
):
    user = authenticate_admin(db, form_data.username, form_data.password)
    if not user:
        user = authenticate_student(db, form_data.username, form_data.password)
        
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["username"]}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/addBooks", status_code=status.HTTP_201_CREATED, tags=["Admin"])
def add_book(book: Books, current_user : Annotated[Admin, Depends(get_current_active_admin)]):
    new_book = models.Books(
        b_id = book.b_id,
        title = book.title,
        author = book.author,
        status = book.status 

    )
    db.add(new_book)
    db.commit()
    return "Book was added successfully"

@app.get("/getBooks/", tags=["Admin"])
def get_all_books(current_user : Annotated[Admin, Depends(get_current_active_admin)]):   
    books = db.query(models.Books).all()
    return books
    
@app.delete("/deleteBook/{title: Str}", tags=["Admin"])
def delete_book(title, current_user : Annotated[Admin, Depends(get_current_active_admin)]):
    del_book = db.query(models.Books).filter(models.Books.title == title).first()
    db.delete(del_book)
    db.commit()
    return delete_book

# Authentication for a student
def get_student(db, username: str):
    res = db.query(models.Students).filter(models.Students.username == username).first()
    if res is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not eligible to access or view the data", headers={"WWW-Authenticate" : "Bearer"})
    return (vars(res))


def authenticate_student(db, username: str, password: str):
    admin = get_student(db, username)
    if not admin:
        return False
    if not verify_password(password, admin["hashed_password"]):
        return False
    return admin

async def get_current_student(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    student = get_student(db, token_data.username)
    if student is None:
        raise credentials_exception
    return student


async def get_current_active_student(
    current_user: Annotated[Admin, Depends(get_current_student)]
):
    # if current_user["disabled"]:
    #     raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.post("/addstudents/", tags=["Admin"])
def add_student(new_student: Students, current_user : Annotated[Admin, Depends(get_current_active_admin)]):
    new_std = models.Students(
        s_id = new_student.s_id,
        s_name = new_student.s_name,
        username = new_student.username,
        email = new_student.email,
        hashed_password = get_password_hash(new_student.hashed_password)
    )
    db.add(new_std)
    db.commit()
    return new_std

@app.get("/viewStudent", tags=["Admin"])
def get_all_students(current_user : Annotated[Admin, Depends(get_current_active_admin)]):
    
    students = db.query(models.Students).all()
    if students is not None:
        return students
    else:
        return f"Student was not found!"


# Issuing book for a student

# @app.post("/issueBook/{s_id}/{b_id}", tags=["Admin"])
# def issue_book_to_std(s_id: int, b_id: int, current_user : Annotated[Admin, Depends(get_current_active_admin)]):
#     book_to_std = models.StudentBooks(
#         s_id = s_id,
#         b_id = b_id,
#         date_of_issue = date.today()
#     )
#     books_len = db.query(models.StudentBooks).filter(models.StudentBooks.s_id == book_to_std.s_id).all()
#     if len(books_len) >= 2:
#         raise HTTPException(status_code=404, detail="Student can't take more than 2 books")
#     db.add(book_to_std)
#     db.commit()
#     return "Issued successfully"


@app.post("/issueBook/{s_id}/{b_id}", tags=["Admin"])
def issue_book_to_std(s_id: int, b_id: int, current_user : Annotated[Admin, Depends(get_current_active_admin)]):
    book_to_std = models.StudentBooks(
        s_id = s_id,
        b_id = b_id,
        date_of_issue = date.today(),
        expected_return_date = date.today()+timedelta(days=10)

    )
    books_len = db.query(models.StudentBooks).filter(models.StudentBooks.s_id == book_to_std.s_id).all()
    if len(books_len) >= 2:
        raise HTTPException(status_code=404, detail="Student can't take more than 2 books")
    
    # Update book status to "issued"
    book = db.query(models.Books).filter(models.Books.b_id == b_id).first()
    if book and book.status == "available":
        book.status = "issued"  # Update status to "issued"
        db.commit()
        db.add(book_to_std)
        db.commit()
        return "Issued successfully"
    elif book and book.status == "issued":
        raise HTTPException(status_code=400, detail="Book is already issued")
    else:
        raise HTTPException(status_code=404, detail="Book not found")
    
    
#Return date of a book

# @app.put("/return_date/{s_id:int}/{b_id:int}/", tags=["Admin"])
# def return_date_of_a_book(s_id,b_id, current_user : Annotated[Admin, Depends(get_current_active_admin)]):
#     find_std_book = db.query(models.StudentBooks).filter(models.StudentBooks.b_id == b_id,models.StudentBooks.s_id == s_id).first()
#     find_std_book.return_date = date.today()

#     if not find_std_book:
#         raise HTTPException(status_code=404, detail="Student not found")

#     db.commit()
#     return find_std_book

@app.put("/return_date/{s_id:int}/{b_id:int}/", tags=["Admin"])
def return_date_of_a_book(s_id,b_id, current_user : Annotated[Admin, Depends(get_current_active_admin)]):
    find_std_book = db.query(models.StudentBooks).filter(models.StudentBooks.b_id == b_id,models.StudentBooks.s_id == s_id).first()

    if not find_std_book:
        raise HTTPException(status_code=404, detail="Student not found")

    # Update book status to "available"
    book = db.query(models.Books).filter(models.Books.b_id == b_id).first()
    if book:
        book.status = "available"  # Update status to "available"
        db.commit()
    else:
        raise HTTPException(status_code=404, detail="Book not found")

    find_std_book.return_date = date.today()
    if (date.today()-find_std_book.expected_return_date).days <=0:
        find_std_book.penalty = 0
    else:
        find_std_book.penalty = ((date.today()-find_std_book.expected_return_date).days)*50
    db.commit()
    return find_std_book


# Issued Books

@app.get("/issuedbooks", response_model=List[Student_Books_join])
def get_student_books():
    student_books = db.query(models.StudentBooks, models.Students, models.Books).join(models.Students).join(models.Books).all()
    if not student_books:
        raise HTTPException(status_code=404, detail="Student not found")
    result = [Student_Books_join(s_id=item.StudentBooks.s_id, b_id = item.StudentBooks.b_id, s_name=item.Students.s_name, date_of_issue=item.StudentBooks.date_of_issue, title = item.Books.title, author=item.Books.author) for item in student_books]

    return result