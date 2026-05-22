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
from fastapi.staticfiles import StaticFiles

# Database
from sqlalchemy import (
    create_engine, Column, String, Boolean, DateTime, 
    Numeric, Integer, ForeignKey, Index, text, func, select
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.pool import StaticPool

# Auth & Security
from passlib.context import CryptContext
from jose import JWTError, jwt
import bcrypt

# Pydantic Models
from pydantic import BaseModel, EmailStr, validator
import json

# Redis alternative - simple in-memory cache
from collections import defaultdict, OrderedDict
import asyncio
import time
import logging

# ════════════════════════════════════════════════════════════════════════════
# 📊 CORE CONFIGURATION
# ════════════════════════════════════════════════════════════════════════════

# Environment variables — barchasi .env faylidan o'qiladi
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY muhit o'zgaruvchisi o'rnatilmagan! .env faylini tekshiring.")

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL muhit o'zgaruvchisi o'rnatilmagan! .env faylini tekshiring.")

JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")

_expire_minutes = os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "1440")
ACCESS_TOKEN_EXPIRE_MINUTES = int(_expire_minutes)

# Simple in-memory cache (Redis alternative for demo)
cache = OrderedDict()
MAX_CACHE_SIZE = 1000

def set_cache(key: str, value: any, ttl: int = 3600):
    if len(cache) >= MAX_CACHE_SIZE:
        cache.popitem(last=False)  # Remove oldest
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

# SQLAlchemy setup
engine = create_engine(
    DATABASE_URL, 
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

# User Model
class User(Base):
    __tablename__ = "users"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String(100), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    full_name = Column(String(255), nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(20), default="viewer", nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    customers = relationship("Customer", back_populates="owner")

# Customer Model
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

# Debt Model
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

# Payment Model
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

# Create tables
Base.metadata.create_all(bind=engine)

# ════════════════════════════════════════════════════════════════════════════
# 🔐 AUTHENTICATION & SECURITY
# ════════════════════════════════════════════════════════════════════════════

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/login")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

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

class UserLogin(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class CustomerCreate(BaseModel):
    full_name: str
    phone: str
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
    # Startup
    print("🚀 Qarizdorlik.uz ishga tushdi!")
    yield
    # Shutdown
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
    # Check existing
    if db.query(User).filter(User.email == user_data.email).first():
        raise HTTPException(status_code=400, detail="Email already exists")
    if db.query(User).filter(User.username == user_data.username).first():
        raise HTTPException(status_code=400, detail="Username already exists")
    
    # Create user
    user = User(
        username=user_data.username,
        email=user_data.email,
        full_name=user_data.full_name,
        hashed_password=get_password_hash(user_data.password),
        role="admin",  # First user is admin
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    
    # Create token
    access_token = create_access_token({"sub": user.id})
    return Token(access_token=access_token)

@app.post("/api/auth/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if not user.is_active:
        raise HTTPException(status_code=401, detail="User is inactive")
    
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
    return customer

@app.get("/api/customers")
def get_customers(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    page: int = 1,
    size: int = 20
):
    offset = (page - 1) * size
    customers = (
        db.query(Customer)
        .filter(Customer.owner_id == current_user.id, Customer.is_active == True)
        .offset(offset)
        .limit(size)
        .all()
    )
    total = db.query(func.count(Customer.id)).filter(Customer.owner_id == current_user.id).scalar()
    
    return {"items": customers, "total": total, "page": page, "size": size}

@app.get("/api/customers/{customer_id}")
def get_customer(
    customer_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    customer = (
        db.query(Customer)
        .filter(Customer.id == customer_id, Customer.owner_id == current_user.id)
        .first()
    )
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")
    return customer

# ════════════════════════════════════════════════════════════════════════════
# 💰 DEBTS ENDPOINTS
# ════════════════════════════════════════════════════════════════════════════

@app.post("/api/debts")
def create_debt(
    debt_data: DebtCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Check customer ownership
    customer = (
        db.query(Customer)
        .filter(Customer.id == debt_data.customer_id, Customer.owner_id == current_user.id)
        .first()
    )
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")
    
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
    
    # Update customer stats
    customer.total_debt += debt_data.amount
    customer.remaining_debt += debt_data.amount
    
    db.commit()
    db.refresh(debt)
    return debt

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
    
    offset = (page - 1) * size
    debts = query.offset(offset).limit(size).all()
    total = query.count()
    
    return {"items": debts, "total": total, "page": page, "size": size}

@app.post("/api/debts/{debt_id}/payments")
def record_payment(
    debt_id: str,
    payment_data: PaymentCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Get debt with customer ownership check
    debt = (
        db.query(Debt)
        .join(Customer, Debt.customer_id == Customer.id)
        .filter(Debt.id == debt_id, Customer.owner_id == current_user.id)
        .first()
    )
    if not debt:
        raise HTTPException(status_code=404, detail="Debt not found")
    
    if payment_data.amount > float(debt.remaining_amount):
        raise HTTPException(status_code=400, detail="Payment exceeds remaining debt")
    
    # Create payment
    payment = Payment(
        debt_id=debt_id,
        amount=payment_data.amount,
        currency=debt.currency,
        method=payment_data.method,
        notes=payment_data.notes,
    )
    db.add(payment)
    
    # Update debt
    debt.remaining_amount -= payment_data.amount
    if float(debt.remaining_amount) <= 0:
        debt.status = "paid"
    else:
        debt.status = "partially_paid"
    
    # Update customer stats
    customer = debt.customer
    customer.total_paid += payment_data.amount
    customer.remaining_debt -= payment_data.amount
    
    db.commit()
    db.refresh(payment)
    return payment

# ════════════════════════════════════════════════════════════════════════════
# 📊 ANALYTICS ENDPOINTS
# ════════════════════════════════════════════════════════════════════════════

@app.get("/api/analytics/dashboard")
def get_dashboard_stats(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Cache check
    cache_key = f"dashboard:{current_user.id}"
    cached = get_cache(cache_key)
    if cached:
        return cached
    
    # Customer stats
    total_customers = db.query(func.count(Customer.id)).filter(
        Customer.owner_id == current_user.id, Customer.is_active == True
    ).scalar()
    
    # Debt stats
    debt_stats = db.query(
        func.count(Debt.id).label("total_debts"),
        func.coalesce(func.sum(Debt.amount), 0).label("total_amount"),
        func.coalesce(func.sum(Debt.remaining_amount), 0).label("remaining_amount")
    ).join(Customer, Debt.customer_id == Customer.id).filter(
        Customer.owner_id == current_user.id
    ).first()
    
    # Payment stats (this month)
    this_month = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    monthly_payments = db.query(
        func.coalesce(func.sum(Payment.amount), 0)
    ).join(Debt, Payment.debt_id == Debt.id).join(
        Customer, Debt.customer_id == Customer.id
    ).filter(
        Customer.owner_id == current_user.id,
        Payment.payment_date >= this_month
    ).scalar()
    
    # Status counts
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
        "status_counts": {status: count for status, count in status_counts},
        "generated_at": datetime.utcnow().isoformat()
    }
    
    # Cache for 5 minutes
    set_cache(cache_key, result, 300)
    return result

# ════════════════════════════════════════════════════════════════════════════
# 🌐 FRONTEND UI
# ════════════════════════════════════════════════════════════════════════════

FRONTEND_HTML = """
<!DOCTYPE html>
<html lang="uz">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Qarizdorlik.uz - Qarzdorlikni Boshqarish</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            theme: {
                extend: {
                    colors: {
                        primary: '#2563eb',
                        secondary: '#1e293b',
                        accent: '#38bdf8',
                        dark: '#0f172a'
                    }
                }
            }
        }
    </script>
    <style>
        .glassmorphism {
            background: rgba(17, 25, 40, 0.85);
            backdrop-filter: blur(16px);
            border: 1px solid rgba(255, 255, 255, 0.1);
        }
        .gradient-bg {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }
    </style>
</head>
<body class="bg-dark text-white min-h-screen">
    <!-- Navigation -->
    <nav class="glassmorphism p-4 mb-8">
        <div class="container mx-auto flex justify-between items-center">
            <h1 class="text-2xl font-bold text-primary">Qarizdorlik.uz</h1>
            <div id="user-menu" class="hidden">
                <span id="username" class="mr-4"></span>
                <button onclick="logout()" class="bg-red-600 px-4 py-2 rounded hover:bg-red-700">
                    Chiqish
                </button>
            </div>
        </div>
    </nav>

    <!-- Login Form -->
    <div id="login-section" class="container mx-auto max-w-md">
        <div class="glassmorphism p-8 rounded-lg">
            <h2 class="text-3xl font-bold mb-6 text-center text-accent">Tizimga Kirish</h2>
            <div id="auth-tabs" class="flex mb-6">
                <button onclick="showLogin()" id="login-tab" 
                        class="flex-1 py-2 bg-primary rounded-l hover:bg-blue-600">Kirish</button>
                <button onclick="showRegister()" id="register-tab" 
                        class="flex-1 py-2 bg-secondary rounded-r hover:bg-gray-600">Ro'yxatdan o'tish</button>
            </div>
            
            <!-- Login -->
            <form id="login-form" onsubmit="handleLogin(event)">
                <div class="mb-4">
                    <input type="text" id="login-username" placeholder="Foydalanuvchi nomi" required
                           class="w-full p-3 rounded bg-secondary border border-gray-600 focus:border-primary text-white">
                </div>
                <div class="mb-6">
                    <input type="password" id="login-password" placeholder="Parol" required
                           class="w-full p-3 rounded bg-secondary border border-gray-600 focus:border-primary text-white">
                </div>
                <button type="submit" class="w-full bg-primary py-3 rounded font-semibold hover:bg-blue-600">
                    Kirish
                </button>
            </form>

            <!-- Register -->
            <form id="register-form" onsubmit="handleRegister(event)" class="hidden">
                <div class="mb-4">
                    <input type="text" id="reg-username" placeholder="Foydalanuvchi nomi" required
                           class="w-full p-3 rounded bg-secondary border border-gray-600 focus:border-primary text-white">
                </div>
                <div class="mb-4">
                    <input type="email" id="reg-email" placeholder="Email" required
                           class="w-full p-3 rounded bg-secondary border border-gray-600 focus:border-primary text-white">
                </div>
                <div class="mb-4">
                    <input type="text" id="reg-fullname" placeholder="To'liq ism" required
                           class="w-full p-3 rounded bg-secondary border border-gray-600 focus:border-primary text-white">
                </div>
                <div class="mb-6">
                    <input type="password" id="reg-password" placeholder="Parol" required
                           class="w-full p-3 rounded bg-secondary border border-gray-600 focus:border-primary text-white">
                </div>
                <button type="submit" class="w-full bg-accent py-3 rounded font-semibold hover:bg-sky-600">
                    Ro'yxatdan O'tish
                </button>
            </form>
        </div>
    </div>

    <!-- Dashboard -->
    <div id="dashboard-section" class="hidden container mx-auto">
        <!-- Stats Cards -->
        <div class="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
            <div class="glassmorphism p-6 rounded-lg">
                <h3 class="text-lg font-semibold text-accent mb-2">Jami Mijozlar</h3>
                <p class="text-3xl font-bold" id="total-customers">0</p>
            </div>
            <div class="glassmorphism p-6 rounded-lg">
                <h3 class="text-lg font-semibold text-accent mb-2">Jami Qarz</h3>
                <p class="text-3xl font-bold" id="total-debt">0</p>
            </div>
            <div class="glassmorphism p-6 rounded-lg">
                <h3 class="text-lg font-semibold text-accent mb-2">Qolgan Qarz</h3>
                <p class="text-3xl font-bold" id="remaining-debt">0</p>
            </div>
            <div class="glassmorphism p-6 rounded-lg">
                <h3 class="text-lg font-semibold text-accent mb-2">Bu Oylik To'lovlar</h3>
                <p class="text-3xl font-bold" id="monthly-payments">0</p>
            </div>
        </div>

        <!-- Quick Actions -->
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
            <button onclick="showAddCustomer()" 
                    class="glassmorphism p-6 rounded-lg hover:bg-primary/20 transition-all">
                <h3 class="text-xl font-semibold mb-2">➕ Mijoz Qo'shish</h3>
                <p class="text-gray-300">Yangi qarzdor mijoz qo'shish</p>
            </button>
            <button onclick="showAddDebt()" 
                    class="glassmorphism p-6 rounded-lg hover:bg-primary/20 transition-all">
                <h3 class="text-xl font-semibold mb-2">💰 Qarz Qo'shish</h3>
                <p class="text-gray-300">Yangi qarz yozib qo'yish</p>
            </button>
            <button onclick="showCustomers()" 
                    class="glassmorphism p-6 rounded-lg hover:bg-primary/20 transition-all">
                <h3 class="text-xl font-semibold mb-2">👥 Mijozlar</h3>
                <p class="text-gray-300">Barcha mijozlarni ko'rish</p>
            </button>
        </div>

        <!-- Recent Debts -->
        <div class="glassmorphism p-6 rounded-lg">
            <h3 class="text-xl font-semibold mb-4 text-accent">So'nggi Qarzlar</h3>
            <div id="recent-debts" class="space-y-3">
                <!-- Dynamic content -->
            </div>
        </div>
    </div>

    <!-- Modals -->
    <div id="modal-overlay" class="hidden fixed inset-0 bg-black/50 backdrop-blur-sm z-50" onclick="closeModal()">
        <div class="flex items-center justify-center min-h-screen p-4">
            <div id="modal-content" class="glassmorphism p-6 rounded-lg max-w-md w-full" onclick="event.stopPropagation()">
                <!-- Dynamic modal content -->
            </div>
        </div>
    </div>

    <script>
        let authToken = localStorage.getItem('auth_token');
        let currentUser = null;

        // Initialize
        if (authToken) {
            checkAuth();
        }

        function showLogin() {
            document.getElementById('login-form').classList.remove('hidden');
            document.getElementById('register-form').classList.add('hidden');
            document.getElementById('login-tab').classList.add('bg-primary');
            document.getElementById('register-tab').classList.remove('bg-primary');
            document.getElementById('register-tab').classList.add('bg-secondary');
        }

        function showRegister() {
            document.getElementById('register-form').classList.remove('hidden');
            document.getElementById('login-form').classList.add('hidden');
            document.getElementById('register-tab').classList.add('bg-primary');
            document.getElementById('login-tab').classList.remove('bg-primary');
            document.getElementById('login-tab').classList.add('bg-secondary');
        }

        async function handleLogin(e) {
            e.preventDefault();
            const formData = new FormData();
            formData.append('username', document.getElementById('login-username').value);
            formData.append('password', document.getElementById('login-password').value);

            try {
                const response = await fetch('/api/auth/login', {
                    method: 'POST',
                    body: formData
                });
                const data = await response.json();
                
                if (response.ok) {
                    authToken = data.access_token;
                    localStorage.setItem('auth_token', authToken);
                    await checkAuth();
                } else {
                    alert(data.detail || 'Login failed');
                }
            } catch (error) {
                alert('Login error: ' + error.message);
            }
        }

        async function handleRegister(e) {
            e.preventDefault();
            const userData = {
                username: document.getElementById('reg-username').value,
                email: document.getElementById('reg-email').value,
                full_name: document.getElementById('reg-fullname').value,
                password: document.getElementById('reg-password').value
            };

            try {
                const response = await fetch('/api/auth/register', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(userData)
                });
                const data = await response.json();
                
                if (response.ok) {
                    authToken = data.access_token;
                    localStorage.setItem('auth_token', authToken);
                    await checkAuth();
                } else {
                    alert(data.detail || 'Registration failed');
                }
            } catch (error) {
                alert('Registration error: ' + error.message);
            }
        }

        async function checkAuth() {
            try {
                const response = await fetch('/api/auth/me', {
                    headers: {'Authorization': `Bearer ${authToken}`}
                });
                
                if (response.ok) {
                    currentUser = await response.json();
                    showDashboard();
                    loadDashboardData();
                } else {
                    logout();
                }
            } catch (error) {
                logout();
            }
        }

        function showDashboard() {
            document.getElementById('login-section').classList.add('hidden');
            document.getElementById('dashboard-section').classList.remove('hidden');
            document.getElementById('user-menu').classList.remove('hidden');
            document.getElementById('username').textContent = currentUser.full_name;
        }

        function logout() {
            localStorage.removeItem('auth_token');
            authToken = null;
            currentUser = null;
            document.getElementById('dashboard-section').classList.add('hidden');
            document.getElementById('login-section').classList.remove('hidden');
            document.getElementById('user-menu').classList.add('hidden');
        }

        async function loadDashboardData() {
            try {
                const response = await fetch('/api/analytics/dashboard', {
                    headers: {'Authorization': `Bearer ${authToken}`}
                });
                const data = await response.json();

                document.getElementById('total-customers').textContent = data.customers.total;
                document.getElementById('total-debt').textContent = formatMoney(data.debts.total_amount);
                document.getElementById('remaining-debt').textContent = formatMoney(data.debts.remaining_amount);
                document.getElementById('monthly-payments').textContent = formatMoney(data.payments.monthly_total);

                await loadRecentDebts();
            } catch (error) {
                console.error('Dashboard load error:', error);
            }
        }

        async function loadRecentDebts() {
            try {
                const response = await fetch('/api/debts?page=1&size=5', {
                    headers: {'Authorization': `Bearer ${authToken}`}
                });
                const data = await response.json();
                
                const container = document.getElementById('recent-debts');
                if (data.items.length === 0) {
                    container.innerHTML = '<p class="text-gray-400">Hozircha qarzlar yo\'q</p>';
                } else {
                    container.innerHTML = data.items.map(debt => `
                        <div class="border-l-4 border-accent pl-4 py-2">
                            <h4 class="font-semibold">${debt.title}</h4>
                            <p class="text-sm text-gray-300">
                                Qarz: ${formatMoney(debt.remaining_amount)} ${debt.currency} 
                                <span class="text-xs text-gray-400">(${debt.status})</span>
                            </p>
                        </div>
                    `).join('');
                }
            } catch (error) {
                console.error('Recent debts load error:', error);
            }
        }

        function formatMoney(amount) {
            return new Intl.NumberFormat('uz-UZ').format(amount);
        }

        function showModal(content) {
            document.getElementById('modal-content').innerHTML = content;
            document.getElementById('modal-overlay').classList.remove('hidden');
        }

        function closeModal() {
            document.getElementById('modal-overlay').classList.add('hidden');
        }

        function showAddCustomer() {
            showModal(`
                <h3 class="text-xl font-bold mb-4 text-accent">Mijoz Qo'shish</h3>
                <form onsubmit="handleAddCustomer(event)">
                    <div class="mb-4">
                        <input type="text" id="customer-name" placeholder="To'liq ism" required
                               class="w-full p-3 rounded bg-secondary border border-gray-600 focus:border-primary text-white">
                    </div>
                    <div class="mb-4">
                        <input type="tel" id="customer-phone" placeholder="Telefon raqam" required
                               class="w-full p-3 rounded bg-secondary border border-gray-600 focus:border-primary text-white">
                    </div>
                    <div class="mb-4">
                        <input type="email" id="customer-email" placeholder="Email (ixtiyoriy)"
                               class="w-full p-3 rounded bg-secondary border border-gray-600 focus:border-primary text-white">
                    </div>
                    <div class="mb-6">
                        <textarea id="customer-address" placeholder="Manzil" rows="2"
                                  class="w-full p-3 rounded bg-secondary border border-gray-600 focus:border-primary text-white"></textarea>
                    </div>
                    <div class="flex gap-3">
                        <button type="submit" class="flex-1 bg-primary py-2 rounded hover:bg-blue-600">
                            Saqlash
                        </button>
                        <button type="button" onclick="closeModal()" class="flex-1 bg-gray-600 py-2 rounded hover:bg-gray-700">
                            Bekor qilish
                        </button>
                    </div>
                </form>
            `);
        }

        async function handleAddCustomer(e) {
            e.preventDefault();
            const customerData = {
                full_name: document.getElementById('customer-name').value,
                phone: document.getElementById('customer-phone').value,
                email: document.getElementById('customer-email').value || null,
                address: document.getElementById('customer-address').value || null
            };

            try {
                const response = await fetch('/api/customers', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${authToken}`
                    },
                    body: JSON.stringify(customerData)
                });

                if (response.ok) {
                    closeModal();
                    loadDashboardData();
                    alert('Mijoz muvaffaqiyatli qo\'shildi!');
                } else {
                    const error = await response.json();
                    alert(error.detail || 'Xatolik yuz berdi');
                }
            } catch (error) {
                alert('Xatolik: ' + error.message);
            }
        }

        // Initialize
        document.addEventListener('DOMContentLoaded', () => {
            if (authToken) {
                checkAuth();
            }
        });
    </script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
def get_frontend():
    return FRONTEND_HTML

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "app": "Qarizdorlik.uz",
        "version": "2.0.0",
        "timestamp": datetime.utcnow().isoformat()
    }

if __name__ == "__main__":
    import uvicorn
    print("🚀 Qarizdorlik.uz ishga tushmoqda...")
    print("📱 Frontend: http://localhost:8000")
    print("📊 API Docs: http://localhost:8000/docs")
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)