from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, Date
from sqlalchemy.orm import relationship

from database import Base, engine

def create_tables():
    Base.metadata.create_all(engine)

class Admin(Base):
    __tablename__ = "admin"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)


class Students(Base):
    __tablename__ = "students"

    s_id = Column(Integer, primary_key=True, index=True)
    s_name = Column(String, index=True)
    username = Column(String)
    email = Column(String)
    hashed_password = Column(String)
    student_books = relationship("StudentBooks", back_populates="student")



class Books(Base):
    __tablename__ = "books"

    b_id = Column(Integer, primary_key=True, index=True)
    title = Column(String)
    author = Column(String)
    status = Column(String)
    status = Column(String)
    student_books = relationship("StudentBooks", back_populates="book")


class StudentBooks(Base):
    __tablename__ = "studentBooks"

    s_no = Column(Integer, primary_key=True, index=True)
    s_id = Column(Integer, ForeignKey("students.s_id"), nullable=False)
    b_id = Column(Integer, ForeignKey("books.b_id"), nullable = False)
    date_of_issue = Column(Date)
    expected_return_date = Column(Date)
    return_date = Column(Date)
    penalty = Column(Integer)
    student = relationship("Students", back_populates="student_books")
    book = relationship("Books", back_populates="student_books")



