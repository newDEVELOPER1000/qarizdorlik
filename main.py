"""
Qarizdorlik.uz - Compact Debt Management System
Bitta faylda to'liq ishlash uchun tayyor tizim
"""

import os
import uuid
import secrets
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Annotated
from contextlib import asynccontextmanager

# FastAPI va Dependencies
from fastapi import (
    FastAPI, Depends, HTTPException, status, Request, Form,
    WebSocket, WebSocketDisconnect
)
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse

# Database
from sqlalchemy import (
    create_engine, Column, String, Boolean, DateTime,
    Numeric, Integer, ForeignKey, Index, text, func, select
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship

# Auth & Security — faqat bir marta import
from passlib.context import CryptContext
from jose import JWTError, jwt

# Pydantic Models
from pydantic import BaseModel
import json

# Redis alternative - simple in-memory cache
from collections import defaultdict, OrderedDict
import asyncio
import time
import logging

# ════════════════════════════════════════════════════════════════════════════
# 📊 CORE CONFIGURATION
# ════════════════════════════════════════════════════════════════════════════

SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY muhit o'zgaruvchisi o'rnatilmagan!")

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL muhit o'zgaruvchisi o'rnatilmagan!")

JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "1440"))

# Simple in-memory cache
cache = OrderedDict()
MAX_CACHE_SIZE = 1000

def set_cache(key: str, value, ttl: int = 3600):
    if len(cache) >= MAX_CACHE_SIZE:
        cache.popitem(last=False)
    cache[key] = {"value": value, "expires": time.time() + ttl}

def get_cache(key: str):
    if key in cache:
        if time.time() < cache[key]["expires"]:
            return cache[key]["value"]
        else:
            del cache[key]
    return None

# ════════════════════════════════════════════════════════════════════════════
# 🗄️ DATABASE MODELS
# ════════════════════════════════════════════════════════════════════════════

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String(100), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    full_name = Column(String(255), nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(20), default="admin", nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    customers = relationship("Customer", back_populates="owner")

class Customer(Base):
    __tablename__ = "customers"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    owner_id = Column(String, ForeignKey("users.id"), nullable=False, index=True)
    full_name = Column(String(255), nullable=False, index=True)
    phone = Column(String(20), nullable=False, index=True)
    email = Column(String(255), nullable=True)
    address = Column(String(500), nullable=True)
    total_debt = Column(Numeric(20, 2), default=0, nullable=False)
    total_paid = Column(Numeric(20, 2), default=0, nullable=False)
    remaining_debt = Column(Numeric(20, 2), default=0, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    owner = relationship("User", back_populates="customers")
    debts = relationship("Debt", back_populates="customer")

class Debt(Base):
    __tablename__ = "debts"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    customer_id = Column(String, ForeignKey("customers.id"), nullable=False, index=True)
    title = Column(String(500), nullable=False)
    description = Column(String(1000), nullable=True)
    amount = Column(Numeric(20, 2), nullable=False)
    remaining_amount = Column(Numeric(20, 2), nullable=False)
    currency = Column(String(3), default="UZS", nullable=False)
    status = Column(String(20), default="active", nullable=False, index=True)
    debt_date = Column(DateTime, default=datetime.utcnow, nullable=False)
    due_date = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    customer = relationship("Customer", back_populates="debts")
    payments = relationship("Payment", back_populates="debt")

class Payment(Base):
    __tablename__ = "payments"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    debt_id = Column(String, ForeignKey("debts.id"), nullable=False, index=True)
    amount = Column(Numeric(20, 2), nullable=False)
    currency = Column(String(3), default="UZS", nullable=False)
    payment_date = Column(DateTime, default=datetime.utcnow, nullable=False)
    method = Column(String(50), default="cash", nullable=False)
    notes = Column(String(500), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    debt = relationship("Debt", back_populates="payments")

Base.metadata.create_all(bind=engine)

# ════════════════════════════════════════════════════════════════════════════
# 🔐 AUTHENTICATION & SECURITY
# ════════════════════════════════════════════════════════════════════════════

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/login")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password[:72], hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password[:72])

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=JWT_ALGORITHM)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = db.query(User).filter(User.id == user_id).first()
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found")
    return user

# ════════════════════════════════════════════════════════════════════════════
# 📝 PYDANTIC SCHEMAS
# ════════════════════════════════════════════════════════════════════════════

class UserCreate(BaseModel):
    username: str
    email: str
    full_name: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class CustomerCreate(BaseModel):
    full_name: str
    phone: str
    email: Optional[str] = None
    address: Optional[str] = None

class CustomerUpdate(BaseModel):
    full_name: Optional[str] = None
    phone: Optional[str] = None
    email: Optional[str] = None
    address: Optional[str] = None

class DebtCreate(BaseModel):
    customer_id: str
    title: str
    description: Optional[str] = None
    amount: float
    currency: str = "UZS"
    due_date: Optional[datetime] = None

class PaymentCreate(BaseModel):
    debt_id: str
    amount: float
    method: str = "cash"
    notes: Optional[str] = None

# ════════════════════════════════════════════════════════════════════════════
# 🚀 FASTAPI APPLICATION
# ════════════════════════════════════════════════════════════════════════════

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("🚀 Qarizdorlik.uz ishga tushdi!")
    yield
    print("🛑 Qarizdorlik.uz to'xtadi!")

app = FastAPI(
    title="Qarizdorlik.uz",
    description="Professional Debt Management Platform",
    version="2.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ════════════════════════════════════════════════════════════════════════════
# 🔑 AUTH ENDPOINTS
# ════════════════════════════════════════════════════════════════════════════

@app.post("/api/auth/register", response_model=Token)
def register(user_data: UserCreate, db: Session = Depends(get_db)):
    try:
        if db.query(User).filter(User.email == user_data.email).first():
            raise HTTPException(status_code=400, detail="Email allaqachon mavjud")
        if db.query(User).filter(User.username == user_data.username).first():
            raise HTTPException(status_code=400, detail="Username allaqachon mavjud")

        user = User(
            username=user_data.username,
            email=user_data.email,
            full_name=user_data.full_name,
            hashed_password=get_password_hash(user_data.password),
            role="admin",
        )
        db.add(user)
        db.commit()
        db.refresh(user)

        access_token = create_access_token({"sub": user.id})
        return Token(access_token=access_token)
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        logging.error(f"Register xatosi: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Server xatosi: {str(e)}")

@app.post("/api/auth/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Login yoki parol xato")
    if not user.is_active:
        raise HTTPException(status_code=401, detail="Foydalanuvchi faol emas")
    access_token = create_access_token({"sub": user.id})
    return Token(access_token=access_token)

@app.get("/api/auth/me")
def get_me(current_user: User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "full_name": current_user.full_name,
        "role": current_user.role
    }

# ════════════════════════════════════════════════════════════════════════════
# 👥 CUSTOMERS ENDPOINTS
# ════════════════════════════════════════════════════════════════════════════

@app.post("/api/customers")
def create_customer(
    customer_data: CustomerCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    customer = Customer(
        owner_id=current_user.id,
        full_name=customer_data.full_name,
        phone=customer_data.phone,
        email=customer_data.email,
        address=customer_data.address,
    )
    db.add(customer)
    db.commit()
    db.refresh(customer)
    return {
        "id": customer.id,
        "full_name": customer.full_name,
        "phone": customer.phone,
        "email": customer.email,
        "address": customer.address,
        "total_debt": float(customer.total_debt or 0),
        "total_paid": float(customer.total_paid or 0),
        "remaining_debt": float(customer.remaining_debt or 0),
        "created_at": customer.created_at.isoformat() if customer.created_at else None,
    }

@app.get("/api/customers")
def get_customers(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    page: int = 1,
    size: int = 20,
    search: Optional[str] = None
):
    offset = (page - 1) * size
    query = db.query(Customer).filter(
        Customer.owner_id == current_user.id,
        Customer.is_active == True
    )
    if search:
        query = query.filter(
            Customer.full_name.ilike(f"%{search}%") |
            Customer.phone.ilike(f"%{search}%")
        )
    total = query.count()
    customers = query.offset(offset).limit(size).all()

    return {
        "items": [
            {
                "id": c.id,
                "full_name": c.full_name,
                "phone": c.phone,
                "email": c.email,
                "address": c.address,
                "total_debt": float(c.total_debt or 0),
                "total_paid": float(c.total_paid or 0),
                "remaining_debt": float(c.remaining_debt or 0),
                "created_at": c.created_at.isoformat() if c.created_at else None,
            }
            for c in customers
        ],
        "total": total,
        "page": page,
        "size": size
    }

@app.get("/api/customers/{customer_id}")
def get_customer(
    customer_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    customer = db.query(Customer).filter(
        Customer.id == customer_id,
        Customer.owner_id == current_user.id
    ).first()
    if not customer:
        raise HTTPException(status_code=404, detail="Mijoz topilmadi")
    return {
        "id": customer.id,
        "full_name": customer.full_name,
        "phone": customer.phone,
        "email": customer.email,
        "address": customer.address,
        "total_debt": float(customer.total_debt or 0),
        "total_paid": float(customer.total_paid or 0),
        "remaining_debt": float(customer.remaining_debt or 0),
        "created_at": customer.created_at.isoformat() if customer.created_at else None,
    }

@app.put("/api/customers/{customer_id}")
def update_customer(
    customer_id: str,
    data: CustomerUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    customer = db.query(Customer).filter(
        Customer.id == customer_id,
        Customer.owner_id == current_user.id
    ).first()
    if not customer:
        raise HTTPException(status_code=404, detail="Mijoz topilmadi")
    if data.full_name is not None:
        customer.full_name = data.full_name
    if data.phone is not None:
        customer.phone = data.phone
    if data.email is not None:
        customer.email = data.email
    if data.address is not None:
        customer.address = data.address
    db.commit()
    return {"message": "Mijoz yangilandi"}

@app.delete("/api/customers/{customer_id}")
def delete_customer(
    customer_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    customer = db.query(Customer).filter(
        Customer.id == customer_id,
        Customer.owner_id == current_user.id
    ).first()
    if not customer:
        raise HTTPException(status_code=404, detail="Mijoz topilmadi")
    customer.is_active = False
    db.commit()
    return {"message": "Mijoz o'chirildi"}

# ════════════════════════════════════════════════════════════════════════════
# 💰 DEBTS ENDPOINTS
# ════════════════════════════════════════════════════════════════════════════

@app.post("/api/debts")
def create_debt(
    debt_data: DebtCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    customer = db.query(Customer).filter(
        Customer.id == debt_data.customer_id,
        Customer.owner_id == current_user.id
    ).first()
    if not customer:
        raise HTTPException(status_code=404, detail="Mijoz topilmadi")

    debt = Debt(
        customer_id=debt_data.customer_id,
        title=debt_data.title,
        description=debt_data.description,
        amount=debt_data.amount,
        remaining_amount=debt_data.amount,
        currency=debt_data.currency,
        due_date=debt_data.due_date,
    )
    db.add(debt)

    # Numeric xatolikni oldini olish uchun float() ishlatamiz
    customer.total_debt = float(customer.total_debt or 0) + debt_data.amount
    customer.remaining_debt = float(customer.remaining_debt or 0) + debt_data.amount

    db.commit()
    db.refresh(debt)
    return {
        "id": debt.id,
        "customer_id": debt.customer_id,
        "title": debt.title,
        "description": debt.description,
        "amount": float(debt.amount),
        "remaining_amount": float(debt.remaining_amount),
        "currency": debt.currency,
        "status": debt.status,
        "due_date": debt.due_date.isoformat() if debt.due_date else None,
        "created_at": debt.created_at.isoformat() if debt.created_at else None,
    }

@app.get("/api/debts")
def get_debts(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    page: int = 1,
    size: int = 20,
    status: Optional[str] = None,
    customer_id: Optional[str] = None
):
    query = (
        db.query(Debt)
        .join(Customer, Debt.customer_id == Customer.id)
        .filter(Customer.owner_id == current_user.id)
    )
    if status:
        query = query.filter(Debt.status == status)
    if customer_id:
        query = query.filter(Debt.customer_id == customer_id)

    total = query.count()
    debts = query.order_by(Debt.created_at.desc()).offset((page - 1) * size).limit(size).all()

    return {
        "items": [
            {
                "id": d.id,
                "customer_id": d.customer_id,
                "title": d.title,
                "description": d.description,
                "amount": float(d.amount),
                "remaining_amount": float(d.remaining_amount),
                "currency": d.currency,
                "status": d.status,
                "due_date": d.due_date.isoformat() if d.due_date else None,
                "created_at": d.created_at.isoformat() if d.created_at else None,
            }
            for d in debts
        ],
        "total": total,
        "page": page,
        "size": size
    }

@app.post("/api/debts/{debt_id}/payments")
def record_payment(
    debt_id: str,
    payment_data: PaymentCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    debt = (
        db.query(Debt)
        .join(Customer, Debt.customer_id == Customer.id)
        .filter(Debt.id == debt_id, Customer.owner_id == current_user.id)
        .first()
    )
    if not debt:
        raise HTTPException(status_code=404, detail="Qarz topilmadi")

    if payment_data.amount > float(debt.remaining_amount):
        raise HTTPException(status_code=400, detail="To'lov qarz miqdoridan ko'p")

    payment = Payment(
        debt_id=debt_id,
        amount=payment_data.amount,
        currency=debt.currency,
        method=payment_data.method,
        notes=payment_data.notes,
    )
    db.add(payment)

    debt.remaining_amount = float(debt.remaining_amount) - payment_data.amount
    if float(debt.remaining_amount) <= 0:
        debt.status = "paid"
    else:
        debt.status = "partially_paid"

    customer = debt.customer
    customer.total_paid = float(customer.total_paid or 0) + payment_data.amount
    customer.remaining_debt = float(customer.remaining_debt or 0) - payment_data.amount

    db.commit()
    db.refresh(payment)
    return {
        "id": payment.id,
        "debt_id": payment.debt_id,
        "amount": float(payment.amount),
        "currency": payment.currency,
        "method": payment.method,
        "notes": payment.notes,
        "payment_date": payment.payment_date.isoformat() if payment.payment_date else None,
    }

@app.get("/api/debts/{debt_id}/payments")
def get_payments(
    debt_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    debt = (
        db.query(Debt)
        .join(Customer, Debt.customer_id == Customer.id)
        .filter(Debt.id == debt_id, Customer.owner_id == current_user.id)
        .first()
    )
    if not debt:
        raise HTTPException(status_code=404, detail="Qarz topilmadi")

    payments = db.query(Payment).filter(Payment.debt_id == debt_id).order_by(Payment.payment_date.desc()).all()
    return [
        {
            "id": p.id,
            "amount": float(p.amount),
            "currency": p.currency,
            "method": p.method,
            "notes": p.notes,
            "payment_date": p.payment_date.isoformat() if p.payment_date else None,
        }
        for p in payments
    ]

# ════════════════════════════════════════════════════════════════════════════
# 📊 ANALYTICS ENDPOINTS
# ════════════════════════════════════════════════════════════════════════════

@app.get("/api/analytics/dashboard")
def get_dashboard_stats(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    cache_key = f"dashboard:{current_user.id}"
    cached = get_cache(cache_key)
    if cached:
        return cached

    total_customers = db.query(func.count(Customer.id)).filter(
        Customer.owner_id == current_user.id, Customer.is_active == True
    ).scalar()

    debt_stats = db.query(
        func.count(Debt.id).label("total_debts"),
        func.coalesce(func.sum(Debt.amount), 0).label("total_amount"),
        func.coalesce(func.sum(Debt.remaining_amount), 0).label("remaining_amount")
    ).join(Customer, Debt.customer_id == Customer.id).filter(
        Customer.owner_id == current_user.id
    ).first()

    this_month = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    monthly_payments = db.query(
        func.coalesce(func.sum(Payment.amount), 0)
    ).join(Debt, Payment.debt_id == Debt.id).join(
        Customer, Debt.customer_id == Customer.id
    ).filter(
        Customer.owner_id == current_user.id,
        Payment.payment_date >= this_month
    ).scalar()

    status_counts = db.query(
        Debt.status, func.count(Debt.id)
    ).join(Customer, Debt.customer_id == Customer.id).filter(
        Customer.owner_id == current_user.id
    ).group_by(Debt.status).all()

    result = {
        "customers": {"total": total_customers or 0},
        "debts": {
            "total": debt_stats.total_debts or 0,
            "total_amount": float(debt_stats.total_amount or 0),
            "remaining_amount": float(debt_stats.remaining_amount or 0),
            "collected_amount": float(debt_stats.total_amount or 0) - float(debt_stats.remaining_amount or 0),
        },
        "payments": {"monthly_total": float(monthly_payments or 0)},
        "status_counts": {s: c for s, c in status_counts},
        "generated_at": datetime.utcnow().isoformat()
    }

    set_cache(cache_key, result, 300)
    return result

# ════════════════════════════════════════════════════════════════════════════
# 🌐 FRONTEND UI
# ════════════════════════════════════════════════════════════════════════════

FRONTEND_HTML = """<!DOCTYPE html>
<html lang="uz">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Qarizdorlik.uz</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@300;400;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg: #0a0e1a;
            --surface: #111827;
            --surface2: #1a2235;
            --border: #1e2d45;
            --primary: #3b82f6;
            --primary-dim: #1d4ed8;
            --accent: #06b6d4;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --text: #e2e8f0;
            --text-dim: #64748b;
            --text-muted: #334155;
            --mono: 'IBM Plex Mono', monospace;
            --sans: 'IBM Plex Sans', sans-serif;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: var(--sans); background: var(--bg); color: var(--text); min-height: 100vh; }

        /* NAV */
        nav {
            background: var(--surface);
            border-bottom: 1px solid var(--border);
            padding: 0 24px;
            height: 56px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            position: sticky; top: 0; z-index: 100;
        }
        .nav-brand { font-family: var(--mono); font-size: 16px; color: var(--accent); letter-spacing: 0.05em; }
        .nav-user { display: flex; align-items: center; gap: 12px; font-size: 14px; color: var(--text-dim); }
        .btn-logout { background: transparent; border: 1px solid var(--border); color: var(--text-dim);
            padding: 6px 14px; border-radius: 6px; cursor: pointer; font-size: 13px; font-family: var(--sans);
            transition: all 0.2s; }
        .btn-logout:hover { border-color: var(--danger); color: var(--danger); }

        /* LAYOUT */
        .container { max-width: 1100px; margin: 0 auto; padding: 0 24px; }
        .page { padding: 32px 0; }

        /* AUTH */
        .auth-wrap { min-height: calc(100vh - 56px); display: flex; align-items: center; justify-content: center; padding: 24px; }
        .auth-card { background: var(--surface); border: 1px solid var(--border); border-radius: 12px;
            padding: 40px; width: 100%; max-width: 420px; }
        .auth-title { font-family: var(--mono); font-size: 22px; color: var(--accent); margin-bottom: 8px; }
        .auth-sub { font-size: 14px; color: var(--text-dim); margin-bottom: 32px; }
        .tab-row { display: flex; border: 1px solid var(--border); border-radius: 8px; overflow: hidden; margin-bottom: 28px; }
        .tab-btn { flex: 1; padding: 10px; border: none; cursor: pointer; font-family: var(--sans); font-size: 14px;
            background: transparent; color: var(--text-dim); transition: all 0.2s; }
        .tab-btn.active { background: var(--primary); color: white; }

        /* FORMS */
        .field { margin-bottom: 16px; }
        .field label { display: block; font-size: 12px; color: var(--text-dim); margin-bottom: 6px; letter-spacing: 0.05em; text-transform: uppercase; }
        .field input, .field textarea, .field select {
            width: 100%; padding: 10px 14px; background: var(--surface2); border: 1px solid var(--border);
            border-radius: 8px; color: var(--text); font-family: var(--sans); font-size: 14px;
            outline: none; transition: border-color 0.2s; }
        .field input:focus, .field textarea:focus, .field select:focus { border-color: var(--primary); }
        .field select option { background: var(--surface2); }

        /* BUTTONS */
        .btn { display: inline-flex; align-items: center; gap: 8px; padding: 10px 20px; border-radius: 8px;
            border: none; cursor: pointer; font-family: var(--sans); font-size: 14px; font-weight: 600;
            transition: all 0.2s; text-decoration: none; }
        .btn-primary { background: var(--primary); color: white; }
        .btn-primary:hover { background: var(--primary-dim); }
        .btn-outline { background: transparent; border: 1px solid var(--border); color: var(--text-dim); }
        .btn-outline:hover { border-color: var(--primary); color: var(--primary); }
        .btn-success { background: var(--success); color: white; }
        .btn-danger { background: transparent; border: 1px solid var(--border); color: var(--danger); }
        .btn-danger:hover { background: var(--danger); color: white; }
        .btn-full { width: 100%; justify-content: center; }
        .btn-sm { padding: 6px 12px; font-size: 13px; }

        /* STATS */
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 28px; }
        .stat-card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 20px 24px; }
        .stat-label { font-size: 12px; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 8px; }
        .stat-value { font-family: var(--mono); font-size: 26px; font-weight: 600; }
        .stat-value.blue { color: var(--primary); }
        .stat-value.cyan { color: var(--accent); }
        .stat-value.green { color: var(--success); }
        .stat-value.yellow { color: var(--warning); }

        /* TOOLBAR */
        .toolbar { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap;
            gap: 12px; margin-bottom: 20px; }
        .toolbar-left { display: flex; align-items: center; gap: 10px; }
        .search-input { padding: 9px 14px; background: var(--surface); border: 1px solid var(--border);
            border-radius: 8px; color: var(--text); font-family: var(--sans); font-size: 14px;
            outline: none; width: 240px; transition: border-color 0.2s; }
        .search-input:focus { border-color: var(--primary); }

        /* TABLE */
        .table-wrap { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; overflow: hidden; }
        table { width: 100%; border-collapse: collapse; }
        th { padding: 12px 16px; text-align: left; font-size: 11px; color: var(--text-dim);
            text-transform: uppercase; letter-spacing: 0.06em; border-bottom: 1px solid var(--border);
            background: var(--surface2); font-weight: 600; }
        td { padding: 14px 16px; font-size: 14px; border-bottom: 1px solid var(--border); vertical-align: middle; }
        tr:last-child td { border-bottom: none; }
        tr:hover td { background: var(--surface2); }
        .td-mono { font-family: var(--mono); font-size: 13px; }

        /* BADGE */
        .badge { display: inline-block; padding: 3px 10px; border-radius: 20px; font-size: 11px; font-weight: 600; }
        .badge-active { background: rgba(59,130,246,0.15); color: var(--primary); }
        .badge-paid { background: rgba(16,185,129,0.15); color: var(--success); }
        .badge-partial { background: rgba(245,158,11,0.15); color: var(--warning); }
        .badge-overdue { background: rgba(239,68,68,0.15); color: var(--danger); }

        /* MODAL */
        .modal-overlay { display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.6);
            backdrop-filter: blur(4px); z-index: 200; align-items: center; justify-content: center; padding: 24px; }
        .modal-overlay.open { display: flex; }
        .modal { background: var(--surface); border: 1px solid var(--border); border-radius: 12px;
            padding: 32px; width: 100%; max-width: 480px; }
        .modal-title { font-family: var(--mono); font-size: 18px; color: var(--accent); margin-bottom: 24px; }
        .modal-actions { display: flex; gap: 10px; margin-top: 24px; }

        /* SECTION TABS */
        .section-tabs { display: flex; gap: 4px; margin-bottom: 24px; background: var(--surface);
            border: 1px solid var(--border); border-radius: 10px; padding: 4px; width: fit-content; }
        .section-tab { padding: 8px 18px; border-radius: 7px; border: none; background: transparent;
            color: var(--text-dim); cursor: pointer; font-family: var(--sans); font-size: 14px; transition: all 0.2s; }
        .section-tab.active { background: var(--primary); color: white; }

        /* EMPTY */
        .empty { padding: 48px 24px; text-align: center; color: var(--text-dim); font-size: 14px; }
        .empty-icon { font-size: 36px; margin-bottom: 12px; }

        /* ACTIONS COL */
        .actions { display: flex; gap: 6px; }

        /* DETAIL PANEL */
        .detail-header { display: flex; align-items: center; gap: 12px; margin-bottom: 28px; }
        .back-btn { background: transparent; border: none; color: var(--text-dim); cursor: pointer;
            font-size: 20px; padding: 4px; }
        .back-btn:hover { color: var(--text); }
        .detail-name { font-size: 22px; font-weight: 700; }
        .detail-phone { font-family: var(--mono); font-size: 14px; color: var(--text-dim); margin-top: 4px; }

        /* RESPONSIVE */
        @media (max-width: 640px) {
            .stats-grid { grid-template-columns: 1fr 1fr; }
            .toolbar { flex-direction: column; align-items: stretch; }
            .search-input { width: 100%; }
        }
    </style>
</head>
<body>
    <nav id="main-nav" class="hidden">
        <div class="nav-brand">qarizdorlik.uz</div>
        <div class="nav-user">
            <span id="nav-username"></span>
            <button class="btn-logout" onclick="logout()">Chiqish</button>
        </div>
    </nav>

    <!-- AUTH -->
    <div id="auth-section" class="auth-wrap">
        <div class="auth-card">
            <div class="auth-title">// qarizdorlik.uz</div>
            <div class="auth-sub">Qarz daftari tizimiga kiring</div>
            <div class="tab-row">
                <button class="tab-btn active" id="tab-login" onclick="switchTab('login')">Kirish</button>
                <button class="tab-btn" id="tab-reg" onclick="switchTab('reg')">Ro'yxat</button>
            </div>

            <form id="login-form" onsubmit="handleLogin(event)">
                <div class="field"><label>Foydalanuvchi nomi</label>
                    <input type="text" id="l-username" required placeholder="username"></div>
                <div class="field"><label>Parol</label>
                    <input type="password" id="l-password" required placeholder="••••••••"></div>
                <button type="submit" class="btn btn-primary btn-full" style="margin-top:8px">Kirish</button>
            </form>

            <form id="reg-form" onsubmit="handleRegister(event)" style="display:none">
                <div class="field"><label>Foydalanuvchi nomi</label>
                    <input type="text" id="r-username" required placeholder="username"></div>
                <div class="field"><label>Email</label>
                    <input type="email" id="r-email" required placeholder="email@mail.com"></div>
                <div class="field"><label>To'liq ism</label>
                    <input type="text" id="r-fullname" required placeholder="Ism Familiya"></div>
                <div class="field"><label>Parol</label>
                    <input type="password" id="r-password" required placeholder="••••••••"></div>
                <button type="submit" class="btn btn-primary btn-full" style="margin-top:8px">Ro'yxatdan o'tish</button>
            </form>
        </div>
    </div>

    <!-- MAIN APP -->
    <div id="app-section" style="display:none">
        <div class="container page">

            <!-- SECTION TABS -->
            <div class="section-tabs">
                <button class="section-tab active" onclick="showSection('dashboard')">Dashboard</button>
                <button class="section-tab" onclick="showSection('customers')">Mijozlar</button>
                <button class="section-tab" onclick="showSection('debts')">Qarzlar</button>
            </div>

            <!-- DASHBOARD -->
            <div id="sec-dashboard">
                <div class="stats-grid">
                    <div class="stat-card"><div class="stat-label">Mijozlar</div><div class="stat-value blue" id="s-customers">—</div></div>
                    <div class="stat-card"><div class="stat-label">Jami qarz</div><div class="stat-value cyan" id="s-total">—</div></div>
                    <div class="stat-card"><div class="stat-label">Qolgan qarz</div><div class="stat-value yellow" id="s-remaining">—</div></div>
                    <div class="stat-card"><div class="stat-label">Bu oy to'landi</div><div class="stat-value green" id="s-monthly">—</div></div>
                </div>
                <div class="toolbar">
                    <span style="font-size:15px;font-weight:600">So'nggi qarzlar</span>
                    <button class="btn btn-primary btn-sm" onclick="openDebtModal()">+ Qarz qo'shish</button>
                </div>
                <div class="table-wrap">
                    <table>
                        <thead><tr><th>Sarlavha</th><th>Qarz</th><th>Qoldi</th><th>Status</th><th>Sana</th></tr></thead>
                        <tbody id="recent-debts-tbody"></tbody>
                    </table>
                </div>
            </div>

            <!-- CUSTOMERS -->
            <div id="sec-customers" style="display:none">
                <div id="customers-list-view">
                    <div class="toolbar">
                        <div class="toolbar-left">
                            <input class="search-input" placeholder="Ism yoki telefon..." id="customer-search" oninput="searchCustomers()">
                        </div>
                        <button class="btn btn-primary btn-sm" onclick="openCustomerModal()">+ Mijoz qo'shish</button>
                    </div>
                    <div class="table-wrap">
                        <table>
                            <thead><tr><th>Ism</th><th>Telefon</th><th>Jami qarz</th><th>Qoldi</th><th>Amallar</th></tr></thead>
                            <tbody id="customers-tbody"></tbody>
                        </table>
                    </div>
                </div>
                <div id="customer-detail-view" style="display:none"></div>
            </div>

            <!-- DEBTS -->
            <div id="sec-debts" style="display:none">
                <div class="toolbar">
                    <div class="toolbar-left">
                        <select id="debt-status-filter" onchange="loadDebts()" style="padding:9px 14px;background:var(--surface);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:14px;outline:none;">
                            <option value="">Barchasi</option>
                            <option value="active">Aktiv</option>
                            <option value="partially_paid">Qisman to'langan</option>
                            <option value="paid">To'liq to'langan</option>
                        </select>
                    </div>
                    <button class="btn btn-primary btn-sm" onclick="openDebtModal()">+ Qarz qo'shish</button>
                </div>
                <div class="table-wrap">
                    <table>
                        <thead><tr><th>Sarlavha</th><th>Mijoz</th><th>Qarz</th><th>Qoldi</th><th>Status</th><th>Amallar</th></tr></thead>
                        <tbody id="debts-tbody"></tbody>
                    </table>
                </div>
            </div>

        </div>
    </div>

    <!-- MODAL -->
    <div class="modal-overlay" id="modal" onclick="closeModal(event)">
        <div class="modal" id="modal-box"></div>
    </div>

    <script>
    let token = localStorage.getItem('token');
    let me = null;
    let customersCache = [];

    const api = async (path, opts = {}) => {
        const res = await fetch('/api' + path, {
            ...opts,
            headers: { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json', ...(opts.headers || {}) }
        });
        if (!res.ok) { const e = await res.json().catch(() => ({})); throw new Error(e.detail || 'Xatolik'); }
        return res.json();
    };

    const fmt = n => new Intl.NumberFormat('uz-UZ').format(Math.round(n || 0));

    function statusBadge(s) {
        const map = { active: ['badge-active','Aktiv'], partially_paid: ['badge-partial','Qisman'], paid: ['badge-paid','To\'liq'] };
        const [cls, label] = map[s] || ['badge-active', s];
        return `<span class="badge ${cls}">${label}</span>`;
    }

    // AUTH
    function switchTab(t) {
        document.getElementById('login-form').style.display = t === 'login' ? '' : 'none';
        document.getElementById('reg-form').style.display = t === 'reg' ? '' : 'none';
        document.getElementById('tab-login').classList.toggle('active', t === 'login');
        document.getElementById('tab-reg').classList.toggle('active', t === 'reg');
    }

    async function handleLogin(e) {
        e.preventDefault();
        const fd = new FormData();
        fd.append('username', document.getElementById('l-username').value);
        fd.append('password', document.getElementById('l-password').value);
        try {
            const res = await fetch('/api/auth/login', { method: 'POST', body: fd });
            const data = await res.json();
            if (!res.ok) throw new Error(data.detail || 'Xatolik');
            token = data.access_token;
            localStorage.setItem('token', token);
            await initApp();
        } catch (err) { alert(err.message); }
    }

    async function handleRegister(e) {
        e.preventDefault();
        try {
            const data = await api('/auth/register', {
                method: 'POST',
                body: JSON.stringify({
                    username: document.getElementById('r-username').value,
                    email: document.getElementById('r-email').value,
                    full_name: document.getElementById('r-fullname').value,
                    password: document.getElementById('r-password').value
                })
            });
            token = data.access_token;
            localStorage.setItem('token', token);
            await initApp();
        } catch (err) { alert(err.message); }
    }

    function logout() {
        localStorage.removeItem('token');
        token = null; me = null;
        document.getElementById('auth-section').style.display = '';
        document.getElementById('auth-section').className = 'auth-wrap';
        document.getElementById('app-section').style.display = 'none';
        document.getElementById('main-nav').classList.add('hidden');
    }

    async function initApp() {
        try {
            me = await api('/auth/me');
            document.getElementById('nav-username').textContent = me.full_name;
            document.getElementById('auth-section').style.display = 'none';
            document.getElementById('app-section').style.display = '';
            document.getElementById('main-nav').classList.remove('hidden');
            await loadDashboard();
            await refreshCustomersCache();
        } catch { logout(); }
    }

    // SECTIONS
    function showSection(name) {
        ['dashboard','customers','debts'].forEach(s => {
            document.getElementById('sec-' + s).style.display = s === name ? '' : 'none';
        });
        document.querySelectorAll('.section-tab').forEach((btn, i) => {
            btn.classList.toggle('active', ['dashboard','customers','debts'][i] === name);
        });
        if (name === 'customers') loadCustomers();
        if (name === 'debts') loadDebts();
    }

    // DASHBOARD
    async function loadDashboard() {
        try {
            const data = await api('/analytics/dashboard');
            document.getElementById('s-customers').textContent = data.customers.total;
            document.getElementById('s-total').textContent = fmt(data.debts.total_amount) + ' UZS';
            document.getElementById('s-remaining').textContent = fmt(data.debts.remaining_amount) + ' UZS';
            document.getElementById('s-monthly').textContent = fmt(data.payments.monthly_total) + ' UZS';
            const debts = await api('/debts?page=1&size=8');
            const tbody = document.getElementById('recent-debts-tbody');
            if (!debts.items.length) {
                tbody.innerHTML = '<tr><td colspan="5"><div class="empty"><div class="empty-icon">📋</div>Hozircha qarzlar yo\'q</div></td></tr>';
            } else {
                tbody.innerHTML = debts.items.map(d => `<tr>
                    <td>${d.title}</td>
                    <td class="td-mono">${fmt(d.amount)} ${d.currency}</td>
                    <td class="td-mono">${fmt(d.remaining_amount)} ${d.currency}</td>
                    <td>${statusBadge(d.status)}</td>
                    <td style="color:var(--text-dim);font-size:13px">${d.created_at ? d.created_at.slice(0,10) : ''}</td>
                </tr>`).join('');
            }
        } catch(e) { console.error(e); }
    }

    // CUSTOMERS CACHE
    async function refreshCustomersCache() {
        try { const d = await api('/customers?size=100'); customersCache = d.items; } catch {}
    }

    // CUSTOMERS LIST
    async function loadCustomers(search = '') {
        const url = '/customers?size=50' + (search ? '&search=' + encodeURIComponent(search) : '');
        try {
            const data = await api(url);
            customersCache = data.items;
            renderCustomersTable(data.items);
        } catch(e) { alert(e.message); }
    }

    function renderCustomersTable(items) {
        const tbody = document.getElementById('customers-tbody');
        if (!items.length) {
            tbody.innerHTML = '<tr><td colspan="5"><div class="empty"><div class="empty-icon">👥</div>Mijozlar yo\'q</div></td></tr>';
            return;
        }
        tbody.innerHTML = items.map(c => `<tr>
            <td><span style="cursor:pointer;color:var(--accent)" onclick="showCustomerDetail('${c.id}')">${c.full_name}</span></td>
            <td class="td-mono">${c.phone}</td>
            <td class="td-mono">${fmt(c.total_debt)} UZS</td>
            <td class="td-mono" style="color:${c.remaining_debt > 0 ? 'var(--warning)' : 'var(--success)'}">${fmt(c.remaining_debt)} UZS</td>
            <td><div class="actions">
                <button class="btn btn-outline btn-sm" onclick="openDebtModal('${c.id}')">+ Qarz</button>
                <button class="btn btn-danger btn-sm" onclick="deleteCustomer('${c.id}')">O'chir</button>
            </div></td>
        </tr>`).join('');
    }

    let searchTimer;
    function searchCustomers() {
        clearTimeout(searchTimer);
        searchTimer = setTimeout(() => loadCustomers(document.getElementById('customer-search').value), 300);
    }

    // CUSTOMER DETAIL
    async function showCustomerDetail(id) {
        try {
            const [c, debtsData] = await Promise.all([
                api('/customers/' + id),
                api('/debts?customer_id=' + id + '&size=50')
            ]);
            document.getElementById('customers-list-view').style.display = 'none';
            const detail = document.getElementById('customer-detail-view');
            detail.style.display = '';

            const debtsHtml = debtsData.items.length ? debtsData.items.map(d => `<tr>
                <td>${d.title}</td>
                <td class="td-mono">${fmt(d.amount)} ${d.currency}</td>
                <td class="td-mono">${fmt(d.remaining_amount)} ${d.currency}</td>
                <td>${statusBadge(d.status)}</td>
                <td><div class="actions">
                    ${d.status !== 'paid' ? `<button class="btn btn-success btn-sm" onclick="openPayModal('${d.id}','${d.remaining_amount}')">To'lov</button>` : ''}
                </div></td>
            </tr>`).join('') :
            '<tr><td colspan="5"><div class="empty"><div class="empty-icon">💳</div>Qarzlar yo\'q</div></td></tr>';

            detail.innerHTML = `
                <div class="detail-header">
                    <button class="back-btn" onclick="backToCustomers()">←</button>
                    <div>
                        <div class="detail-name">${c.full_name}</div>
                        <div class="detail-phone">${c.phone}${c.email ? ' · ' + c.email : ''}</div>
                    </div>
                </div>
                <div class="stats-grid" style="margin-bottom:24px">
                    <div class="stat-card"><div class="stat-label">Jami qarz</div><div class="stat-value cyan">${fmt(c.total_debt)} UZS</div></div>
                    <div class="stat-card"><div class="stat-label">To'landi</div><div class="stat-value green">${fmt(c.total_paid)} UZS</div></div>
                    <div class="stat-card"><div class="stat-label">Qoldi</div><div class="stat-value yellow">${fmt(c.remaining_debt)} UZS</div></div>
                </div>
                <div class="toolbar">
                    <span style="font-weight:600">Qarzlar tarixi</span>
                    <button class="btn btn-primary btn-sm" onclick="openDebtModal('${c.id}')">+ Qarz qo'shish</button>
                </div>
                <div class="table-wrap">
                    <table><thead><tr><th>Sarlavha</th><th>Qarz</th><th>Qoldi</th><th>Status</th><th>Amal</th></tr></thead>
                    <tbody>${debtsHtml}</tbody></table>
                </div>`;
        } catch(e) { alert(e.message); }
    }

    function backToCustomers() {
        document.getElementById('customers-list-view').style.display = '';
        document.getElementById('customer-detail-view').style.display = 'none';
        loadCustomers();
    }

    // DEBTS LIST
    async function loadDebts() {
        const status = document.getElementById('debt-status-filter').value;
        const url = '/debts?size=50' + (status ? '&status=' + status : '');
        try {
            const data = await api(url);
            const tbody = document.getElementById('debts-tbody');
            if (!data.items.length) {
                tbody.innerHTML = '<tr><td colspan="6"><div class="empty"><div class="empty-icon">💰</div>Qarzlar yo\'q</div></td></tr>';
                return;
            }
            // Get customer names
            const custMap = {};
            customersCache.forEach(c => custMap[c.id] = c.full_name);
            tbody.innerHTML = data.items.map(d => `<tr>
                <td>${d.title}</td>
                <td style="color:var(--text-dim)">${custMap[d.customer_id] || '—'}</td>
                <td class="td-mono">${fmt(d.amount)} ${d.currency}</td>
                <td class="td-mono" style="color:${d.remaining_amount > 0 ? 'var(--warning)' : 'var(--success)'}">${fmt(d.remaining_amount)} ${d.currency}</td>
                <td>${statusBadge(d.status)}</td>
                <td><div class="actions">
                    ${d.status !== 'paid' ? `<button class="btn btn-success btn-sm" onclick="openPayModal('${d.id}','${d.remaining_amount}')">To'lov</button>` : ''}
                </div></td>
            </tr>`).join('');
        } catch(e) { alert(e.message); }
    }

    // MODALS
    function openModal(html) {
        document.getElementById('modal-box').innerHTML = html;
        document.getElementById('modal').classList.add('open');
    }
    function closeModal(e) {
        if (!e || e.target === document.getElementById('modal')) {
            document.getElementById('modal').classList.remove('open');
        }
    }

    function openCustomerModal() {
        openModal(`
            <div class="modal-title">// Mijoz qo'shish</div>
            <form onsubmit="submitCustomer(event)">
                <div class="field"><label>To'liq ism *</label><input id="m-cname" required placeholder="Ism Familiya"></div>
                <div class="field"><label>Telefon *</label><input id="m-cphone" required placeholder="+998901234567"></div>
                <div class="field"><label>Email</label><input id="m-cemail" type="email" placeholder="email@mail.com"></div>
                <div class="field"><label>Manzil</label><input id="m-caddr" placeholder="Shahar, ko'cha"></div>
                <div class="modal-actions">
                    <button type="submit" class="btn btn-primary" style="flex:1">Saqlash</button>
                    <button type="button" class="btn btn-outline" onclick="closeModal()">Bekor</button>
                </div>
            </form>`);
    }

    async function submitCustomer(e) {
        e.preventDefault();
        try {
            await api('/customers', { method: 'POST', body: JSON.stringify({
                full_name: document.getElementById('m-cname').value,
                phone: document.getElementById('m-cphone').value,
                email: document.getElementById('m-cemail').value || null,
                address: document.getElementById('m-caddr').value || null
            })});
            closeModal();
            await refreshCustomersCache();
            loadCustomers();
            loadDashboard();
            alert('Mijoz qo\'shildi!');
        } catch(e) { alert(e.message); }
    }

    async function deleteCustomer(id) {
        if (!confirm('Mijozni o\'chirmoqchimisiz?')) return;
        try {
            await api('/customers/' + id, { method: 'DELETE' });
            loadCustomers();
            loadDashboard();
        } catch(e) { alert(e.message); }
    }

    function openDebtModal(customerId = '') {
        const custOptions = customersCache.map(c =>
            `<option value="${c.id}" ${c.id === customerId ? 'selected' : ''}>${c.full_name} (${c.phone})</option>`
        ).join('');
        openModal(`
            <div class="modal-title">// Qarz qo'shish</div>
            <form onsubmit="submitDebt(event)">
                <div class="field"><label>Mijoz *</label>
                    <select id="m-dcust" required style="width:100%;padding:10px 14px;background:var(--surface2);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:14px;outline:none">
                        <option value="">— Tanlang —</option>${custOptions}
                    </select></div>
                <div class="field"><label>Sarlavha *</label><input id="m-dtitle" required placeholder="Qarz sababi"></div>
                <div class="field"><label>Miqdor (UZS) *</label><input id="m-damount" required type="number" min="1" placeholder="1000000"></div>
                <div class="field"><label>Izoh</label><input id="m-ddesc" placeholder="Qo'shimcha ma'lumot"></div>
                <div class="field"><label>Muddat</label><input id="m-ddue" type="date"></div>
                <div class="modal-actions">
                    <button type="submit" class="btn btn-primary" style="flex:1">Saqlash</button>
                    <button type="button" class="btn btn-outline" onclick="closeModal()">Bekor</button>
                </div>
            </form>`);
    }

    async function submitDebt(e) {
        e.preventDefault();
        try {
            await api('/debts', { method: 'POST', body: JSON.stringify({
                customer_id: document.getElementById('m-dcust').value,
                title: document.getElementById('m-dtitle').value,
                amount: parseFloat(document.getElementById('m-damount').value),
                description: document.getElementById('m-ddesc').value || null,
                due_date: document.getElementById('m-ddue').value || null,
                currency: 'UZS'
            })});
            closeModal();
            loadDashboard();
            loadDebts();
            refreshCustomersCache();
            alert('Qarz qo\'shildi!');
        } catch(e) { alert(e.message); }
    }

    function openPayModal(debtId, remaining) {
        openModal(`
            <div class="modal-title">// To'lov qilish</div>
            <form onsubmit="submitPayment(event,'${debtId}')">
                <div class="field"><label>Qolgan qarz</label>
                    <div style="font-family:var(--mono);font-size:20px;color:var(--warning);margin-bottom:16px">${fmt(remaining)} UZS</div></div>
                <div class="field"><label>To'lov miqdori *</label>
                    <input id="m-pamount" required type="number" min="1" max="${remaining}" placeholder="${fmt(remaining)}"></div>
                <div class="field"><label>To'lov usuli</label>
                    <select id="m-pmethod" style="width:100%;padding:10px 14px;background:var(--surface2);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:14px;outline:none">
                        <option value="cash">Naqd</option>
                        <option value="card">Karta</option>
                        <option value="transfer">O'tkazma</option>
                    </select></div>
                <div class="field"><label>Izoh</label><input id="m-pnotes" placeholder="Ixtiyoriy"></div>
                <div class="modal-actions">
                    <button type="submit" class="btn btn-success" style="flex:1">To'lov qilish</button>
                    <button type="button" class="btn btn-outline" onclick="closeModal()">Bekor</button>
                </div>
            </form>`);
    }

    async function submitPayment(e, debtId) {
        e.preventDefault();
        try {
            await api('/debts/' + debtId + '/payments', { method: 'POST', body: JSON.stringify({
                debt_id: debtId,
                amount: parseFloat(document.getElementById('m-pamount').value),
                method: document.getElementById('m-pmethod').value,
                notes: document.getElementById('m-pnotes').value || null
            })});
            closeModal();
            loadDashboard();
            loadDebts();
            refreshCustomersCache();
            alert('To\'lov qabul qilindi!');
        } catch(e) { alert(e.message); }
    }

    // INIT
    if (token) initApp();
    </script>
</body>
</html>"""

@app.get("/", response_class=HTMLResponse)
def get_frontend():
    return FRONTEND_HTML

@app.get("/health")
def health_check():
    return {"status": "healthy", "app": "Qarizdorlik.uz", "version": "2.0.0", "timestamp": datetime.utcnow().isoformat()}

if __name__ == "__main__":
    import uvicorn
    print("🚀 Qarizdorlik.uz ishga tushmoqda...")
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)