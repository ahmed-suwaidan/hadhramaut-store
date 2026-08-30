import os
import sqlite3
import json
import time
import re
import hashlib
import secrets
import urllib.parse
from collections import defaultdict
from typing import Optional
from fastapi import FastAPI, HTTPException, Request, Header, Depends, status
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

BASE_DIR = r"C:\Users\Administrator\Desktop\hadhramaut_store"
DB_PATH = os.path.join(BASE_DIR, "store.db")
if not os.path.exists(DB_PATH):
    alt_db = os.path.join(BASE_DIR, "database.db")
    if os.path.exists(alt_db):
        DB_PATH = alt_db

ADMIN_SECRET_KEY = os.getenv("ADMIN_SECRET_KEY", "Hadramaut#Secure@2026")
MY_WHATSAPP_PHONE = "967783604947"
ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp"}
MAX_FILE_SIZE = 3 * 1024 * 1024  # 3MB

app = FastAPI(title="متجر حضرموت الذكي - Secure Production", docs_url=None, redoc_url=None, openapi_url=None)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

uploads_dir = os.path.join(BASE_DIR, "uploads")
if not os.path.exists(uploads_dir):
    os.makedirs(uploads_dir, exist_ok=True)
app.mount("/uploads", StaticFiles(directory=uploads_dir), name="uploads")

ACTIVE_MERCHANT = {"id": 1, "phone": "770000000", "name": "كشخه"}

# --- دوال الأمان والتشفير ---
def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
    return f"{salt}${key.hex()}"

def verify_password(password: str, stored_hash: str) -> bool:
    if not stored_hash:
        return False
    if "$" not in stored_hash:
        return secrets.compare_digest(password, stored_hash)
    try:
        salt, key_hex = stored_hash.split("$", 1)
        new_key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
        return secrets.compare_digest(new_key.hex(), key_hex)
    except Exception:
        return False

# فحص صلاحيات الإدارة الإلزامي
def require_admin(request: Request, x_admin_key: Optional[str] = Header(None, alias="x-admin-key")):
    key = x_admin_key or request.query_params.get("admin_key") or request.query_params.get("key")
    if not key or not secrets.compare_digest(key, ADMIN_SECRET_KEY):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="غير مصرح: المفتاح السري للإدارة مفقود أو غير صحيح"
        )
    return True

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def safe_add_column(cursor, table, col_def):
    try:
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {col_def}")
    except Exception:
        pass

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            merchant_id INTEGER,
            merchant_phone TEXT,
            name TEXT NOT NULL,
            price REAL NOT NULL,
            description TEXT,
            category TEXT,
            image_url TEXT,
            stock INTEGER DEFAULT 10
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            merchant_id INTEGER,
            merchant_phone TEXT,
            customer_name TEXT NOT NULL,
            phone TEXT NOT NULL,
            address TEXT NOT NULL,
            items TEXT NOT NULL,
            total_price REAL NOT NULL,
            payment_method TEXT DEFAULT 'الدفع عند الاستلام',
            status TEXT DEFAULT 'قيد الانتظار',
            marketer_code TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS merchants (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            shop_name TEXT,
            phone TEXT UNIQUE NOT NULL,
            location TEXT,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS marketers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            code TEXT UNIQUE NOT NULL,
            phone TEXT,
            role TEXT DEFAULT 'member',
            leader_code TEXT,
            commission_rate REAL DEFAULT 7.0,
            sales_count INTEGER DEFAULT 0,
            total_earnings REAL DEFAULT 0,
            paid_earnings REAL DEFAULT 0,
            account_name TEXT,
            account_number TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    safe_add_column(cursor, "products", "merchant_id INTEGER")
    safe_add_column(cursor, "products", "merchant_phone TEXT")
    safe_add_column(cursor, "orders", "merchant_id INTEGER")
    safe_add_column(cursor, "orders", "merchant_phone TEXT")
    safe_add_column(cursor, "orders", "payment_method TEXT")
    safe_add_column(cursor, "orders", "marketer_code TEXT")
    safe_add_column(cursor, "merchants", "name TEXT")
    safe_add_column(cursor, "merchants", "shop_name TEXT")
    safe_add_column(cursor, "merchants", "location TEXT")
    safe_add_column(cursor, "marketers", "role TEXT DEFAULT 'member'")
    safe_add_column(cursor, "marketers", "leader_code TEXT")
    safe_add_column(cursor, "marketers", "sales_count INTEGER DEFAULT 0")
    safe_add_column(cursor, "marketers", "paid_earnings REAL DEFAULT 0")
    safe_add_column(cursor, "marketers", "account_name TEXT")
    safe_add_column(cursor, "marketers", "account_number TEXT")
    conn.commit()
    conn.close()

init_db()

def to_int(val):
    if val is None:
        return None
    try:
        return int(val)
    except (ValueError, TypeError):
        return None

def to_float(val):
    if val is None:
        return None
    try:
        return float(val)
    except (ValueError, TypeError):
        return None

async def parse_body(request: Request):
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            return await request.json()
        except Exception:
            return {}
    elif "multipart/form-data" in content_type or "application/x-www-form-urlencoded" in content_type:
        form = await request.form()
        return dict(form)
    return {}

def extract_merchant(request: Request, body: dict = None):
    b = body or {}
    m_id = (
        request.query_params.get("merchant_id") or 
        request.query_params.get("id") or 
        request.headers.get("x-merchant-id") or 
        request.cookies.get("merchant_id") or 
        b.get("merchant_id") or 
        b.get("merchantId")
    )
    m_phone = (
        request.query_params.get("phone") or 
        request.query_params.get("merchant_phone") or 
        request.headers.get("x-merchant-phone") or 
        request.cookies.get("merchant_phone") or 
        b.get("merchant_phone") or 
        b.get("phone")
    )
    if not m_id and not m_phone:
        m_id = ACTIVE_MERCHANT.get("id")
        m_phone = ACTIVE_MERCHANT.get("phone")
    return m_id, m_phone

# --- 1. التحقق من صلاحيات المدير ---
@app.api_route("/api/auth/admin", methods=["GET", "POST"])
@app.api_route("/api/admin/auth", methods=["GET", "POST"])
@app.api_route("/api/admin/login", methods=["GET", "POST"])
async def verify_admin_auth(request: Request, x_admin_key: Optional[str] = Header(None, alias="x-admin-key")):
    data = await parse_body(request)
    key = x_admin_key or data.get("key") or data.get("password") or data.get("adminKey") or request.query_params.get("key")
    if key and secrets.compare_digest(key, ADMIN_SECRET_KEY):
        return {"status": "ok", "authenticated": True, "success": True, "ok": True}
    raise HTTPException(status_code=401, detail="المفتاح السري غير صحيح")

# --- 2. احتساب وتوزيع الأرباح فورياً (محمي) ---
@app.post("/api/admin/process-whatsapp", dependencies=[Depends(require_admin)])
@app.post("/api/admin/distribute-profit", dependencies=[Depends(require_admin)])
async def process_whatsapp_distribution(request: Request):
    data = await parse_body(request)
    text = data.get("text") or data.get("message") or ""
    override_code = str(data.get("marketer_code") or "").strip().upper()
    override_total = to_float(data.get("total_price"))

    if not text and not override_total:
        raise HTTPException(status_code=400, detail="يرجى لصق نص رسالة الطلب")

    total = 0.0
    if override_total:
        total = override_total
    else:
        total_match = re.search(r'(?:الإجمالي|المستحق|المبلغ|بإجمالي|الإجمالي المستحق)[:\s\*]*([0-9,]+(?:\.[0-9]+)?)', text)
        if total_match:
            total = float(total_match.group(1).replace(',', ''))
        else:
            num_match = re.search(r'([0-9,]+(?:\.[0-9]+)?)\s*(?:ر\.ي|ريال)', text)
            if num_match:
                total = float(num_match.group(1).replace(',', ''))

    marketer_code = override_code
    if not marketer_code:
        code_match = re.search(r'(?:كود المسوق|المسوق|كود)[:\s\*]*([A-Za-z0-9\-_]+)', text)
        if code_match:
            marketer_code = code_match.group(1).strip().upper()
            if marketer_code in ['مباشر', 'DIRECT', 'NONE', '']:
                marketer_code = ""

    cust_name = "عميل واتساب"
    name_match = re.search(r'(?:المشتري|باسم|الاسم)[:\s\*]*([^\n\r,]+)', text)
    if name_match:
        cust_name = name_match.group(1).replace('*', '').strip()

    phone = ""
    phone_match = re.search(r'(?:الهاتف|رقم الهاتف|جوال)[:\s\*]*([0-9\+]+)', text)
    if phone_match:
        phone = phone_match.group(1).strip()

    marketer_earn = 0.0
    leader_earn = 0.0
    marketer_name = "مبيعة مباشرة (بدون مسوق)"
    leader_name = "لا يوجد"
    
    conn = get_db()
    cursor = conn.cursor()

    if marketer_code:
        m = cursor.execute("SELECT * FROM marketers WHERE code = ?", (marketer_code,)).fetchone()
        if m:
            marketer_name = m["name"]
            if m["role"] == "leader":
                leader_name = m["name"]
                leader_earn = total * 0.10
                cursor.execute("UPDATE marketers SET sales_count = sales_count + 1, total_earnings = total_earnings + ? WHERE id = ?", (leader_earn, m["id"]))
            else:
                marketer_earn = total * 0.07
                cursor.execute("UPDATE marketers SET sales_count = sales_count + 1, total_earnings = total_earnings + ? WHERE id = ?", (marketer_earn, m["id"]))
                
                l_code = m["leader_code"]
                if not l_code and "-" in marketer_code:
                    l_code = marketer_code.split("-")[0]
                
                if l_code:
                    lead = cursor.execute("SELECT * FROM marketers WHERE code = ?", (l_code,)).fetchone()
                    if lead:
                        leader_name = lead["name"]
                        leader_earn = total * 0.03
                        cursor.execute("UPDATE marketers SET total_earnings = total_earnings + ? WHERE id = ?", (leader_earn, lead["id"]))
        else:
            if "-" in marketer_code:
                l_code = marketer_code.split("-")[0]
                lead = cursor.execute("SELECT * FROM marketers WHERE code = ?", (l_code,)).fetchone()
                if lead:
                    leader_name = lead["name"]
                    leader_earn = total * 0.03
                    cursor.execute("UPDATE marketers SET total_earnings = total_earnings + ? WHERE id = ?", (leader_earn, lead["id"]))
            marketer_earn = total * 0.07
            marketer_name = f"كود ({marketer_code})"

    platform_profit = total * 0.05
    merchant_due = total * 0.85

    cursor.execute("""
        INSERT INTO orders (customer_name, phone, address, items, total_price, payment_method, marketer_code, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (cust_name, phone, "حضرموت", text or "طلب واتساب فوري", total, "واتساب", marketer_code or "مباشر", "مكتمل وموزع"))
    conn.commit()
    conn.close()

    return {
        "status": "success",
        "message": "تم احتساب وتوزيع أرباح البيعة فوراً!",
        "breakdown": {
            "total": total,
            "marketer_code": marketer_code or "مباشر",
            "marketer_name": marketer_name,
            "marketer_earn": marketer_earn,
            "leader_name": leader_name,
            "leader_earn": leader_earn,
            "platform_profit": platform_profit,
            "merchant_due": merchant_due,
            "customer_name": cust_name
        }
    }

# --- 3. بيانات لوحة الإدارة الشاملة (محمية) ---
@app.get("/api/admin/dashboard", dependencies=[Depends(require_admin)])
@app.get("/api/admin/data", dependencies=[Depends(require_admin)])
@app.get("/api/admin/stats", dependencies=[Depends(require_admin)])
def get_admin_data():
    conn = get_db()
    cursor = conn.cursor()
    
    orders = [dict(r) for r in cursor.execute("SELECT * FROM orders ORDER BY id DESC").fetchall()]
    
    cursor.execute("""
        SELECT p.*, COALESCE(m.shop_name, m.name, 'متجر عام') as shop_name, COALESCE(m.phone, p.merchant_phone) as shop_phone 
        FROM products p 
        LEFT JOIN merchants m ON p.merchant_id = m.id OR p.merchant_phone = m.phone 
        ORDER BY p.id DESC
    """)
    products = [dict(r) for r in cursor.fetchall()]
    merchants = [dict(r) for r in cursor.execute("SELECT id, name, shop_name, phone, location, created_at FROM merchants ORDER BY id DESC").fetchall()]
    
    marketers_raw = [dict(r) for r in cursor.execute("SELECT * FROM marketers ORDER BY role DESC, id DESC").fetchall()]
    marketers = []
    for m in marketers_raw:
        t_earn = to_float(m.get("total_earnings")) or 0.0
        p_earn = to_float(m.get("paid_earnings")) or 0.0
        m["remaining_balance"] = max(0.0, t_earn - p_earn)
        marketers.append(m)
        
    conn.close()

    total_sales = sum(to_float(o.get("total_price")) or 0.0 for o in orders)
    platform_profit = total_sales * 0.05
    merchants_dues = total_sales * 0.85
    marketers_commission = total_sales * 0.10

    sales_by_item = defaultdict(lambda: {"qty": 0, "total": 0.0, "shop": "متجر عام"})
    for o in orders:
        try:
            items_list = json.loads(o.get("items") or "[]")
            if isinstance(items_list, list):
                for it in items_list:
                    p_name = it.get("name") or "سلعة"
                    p_qty = to_int(it.get("quantity")) or 1
                    p_price = to_float(it.get("price")) or 0.0
                    p_shop = it.get("shop_name") or "متجر عام"
                    
                    sales_by_item[p_name]["qty"] += p_qty
                    sales_by_item[p_name]["total"] += (p_qty * p_price)
                    sales_by_item[p_name]["shop"] = p_shop
        except Exception:
            continue

    top_products = [
        {"name": k, "qty": v["qty"], "total": v["total"], "shop": v["shop"]}
        for k, v in sorted(sales_by_item.items(), key=lambda x: x[1]["qty"], reverse=True)
    ][:6]

    return {
        "status": "success",
        "success": True,
        "ok": True,
        "orders": orders,
        "products": products,
        "merchants": merchants,
        "marketers": marketers,
        "top_products": top_products,
        "total_sales": total_sales,
        "platform_profit": platform_profit,
        "merchants_dues": merchants_dues,
        "marketers_commission": marketers_commission,
        "orders_count": len(orders),
        "products_count": len(products),
        "merchants_count": len(merchants),
        "marketers_count": len(marketers)
    }

# تسليم وصرف الأرباح
@app.post("/api/admin/marketers/{marketer_id}/payout", dependencies=[Depends(require_admin)])
async def marketer_payout(marketer_id: int, request: Request):
    data = await parse_body(request)
    amount = to_float(data.get("amount")) or 0.0
    if amount <= 0:
        raise HTTPException(status_code=400, detail="المبلغ المطلوب صرفه غير صحيح")

    conn = get_db()
    cursor = conn.cursor()
    m = cursor.execute("SELECT name, total_earnings, paid_earnings FROM marketers WHERE id = ?", (marketer_id,)).fetchone()
    if not m:
        conn.close()
        raise HTTPException(status_code=404, detail="المسوق غير موجود")

    cursor.execute("UPDATE marketers SET paid_earnings = paid_earnings + ? WHERE id = ?", (amount, marketer_id))
    conn.commit()
    conn.close()
    return {"status": "success", "message": f"تم بنجاح تسجيل تسليم مبلغ {amount:,.0f} ر.ي للمسوق {m['name']}"}

# تحديث بيانات الحساب المالي
@app.post("/api/admin/marketers/{marketer_id}/update-account", dependencies=[Depends(require_admin)])
async def update_marketer_account(marketer_id: int, request: Request):
    data = await parse_body(request)
    acc_name = data.get("account_name") or ""
    acc_num = data.get("account_number") or ""

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE marketers SET account_name = ?, account_number = ? WHERE id = ?", (acc_name, acc_num, marketer_id))
    conn.commit()
    conn.close()
    return {"status": "success", "message": "تم تحديث بيانات الحساب المالي بنجاح!"}

# إضافة قائد أو مسوق
@app.post("/api/admin/marketers", dependencies=[Depends(require_admin)])
async def add_marketer(request: Request):
    data = await parse_body(request)
    name = data.get("name") or "مسوق جديد"
    code = str(data.get("code") or "").strip().upper()
    phone = data.get("phone") or ""
    role = data.get("role") or "member"
    leader_code = str(data.get("leader_code") or "").strip().upper() if role == "member" else None
    commission_rate = to_float(data.get("commission_rate")) or (3.0 if role == "leader" else 7.0)
    acc_name = data.get("account_name") or ""
    acc_num = data.get("account_number") or ""

    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO marketers (name, code, phone, role, leader_code, commission_rate, account_name, account_number)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (name, code, phone, role, leader_code, commission_rate, acc_name, acc_num))
        conn.commit()
        m_id = cursor.lastrowid
        conn.close()
        return {"status": "success", "message": "تمت إضافة المسوق وتثبيت حسابه بنجاح", "id": m_id}
    except Exception:
        conn.close()
        raise HTTPException(status_code=400, detail="كود المسوق مسجل مسبقاً")

@app.post("/api/admin/marketers/{marketer_id}/promote", dependencies=[Depends(require_admin)])
async def promote_marketer(marketer_id: int, request: Request):
    data = await parse_body(request)
    new_leader_code = str(data.get("new_code") or "").strip().upper()
    if not new_leader_code:
        raise HTTPException(status_code=400, detail="يرجى كتابة الكود الجديد للقائد")

    conn = get_db()
    cursor = conn.cursor()
    exist = cursor.execute("SELECT id FROM marketers WHERE code = ? AND id != ?", (new_leader_code, marketer_id)).fetchone()
    if exist:
        conn.close()
        raise HTTPException(status_code=400, detail="كود القائد الجديد مستخدم مسبقاً")

    cursor.execute("""
        UPDATE marketers 
        SET role = 'leader', code = ?, leader_code = NULL, commission_rate = 3.0 
        WHERE id = ?
    """, (new_leader_code, marketer_id))
    conn.commit()
    conn.close()
    return {"status": "success", "message": f"تمت ترقية المسوق إلى قائد فريق بنجاح بكود: {new_leader_code}"}

@app.delete("/api/admin/marketers/{marketer_id}", dependencies=[Depends(require_admin)])
@app.post("/api/admin/marketers/{marketer_id}/delete", dependencies=[Depends(require_admin)])
def delete_marketer(marketer_id: int):
    conn = get_db()
    cursor = conn.cursor()
    m = cursor.execute("SELECT code, role FROM marketers WHERE id = ?", (marketer_id,)).fetchone()
    if m and m["role"] == "leader":
        cursor.execute("UPDATE marketers SET leader_code = NULL WHERE leader_code = ?", (m["code"],))
    cursor.execute("DELETE FROM marketers WHERE id = ?", (marketer_id,))
    conn.commit()
    conn.close()
    return {"status": "success", "message": "تم حذف الحساب بنجاح"}

# تسجيل تاجر جديد (مع تشفير كلمة المرور)
@app.post("/api/admin/merchants/add", dependencies=[Depends(require_admin)])
@app.post("/api/merchants/register")
async def register_merchant(request: Request):
    data = await parse_body(request)
    name = data.get("shop_name") or data.get("name") or "محل تجاري"
    phone = str(data.get("phone", "")).strip()
    location = data.get("location") or "حضرموت"
    raw_password = str(data.get("password", "123456")).strip()
    hashed_pwd = hash_password(raw_password)

    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO merchants (name, shop_name, phone, location, password) VALUES (?, ?, ?, ?, ?)",
                       (name, name, phone, location, hashed_pwd))
        conn.commit()
        m_id = cursor.lastrowid
        conn.close()
        return {"status": "success", "message": "تم فتح وتسجيل حساب التاجر وتشفير بياناته بنجاح!", "merchant_id": m_id, "phone": phone, "name": name}
    except Exception:
        conn.close()
        raise HTTPException(status_code=400, detail="رقم الهاتف مسجل لتاجر مسبقاً")

# تسجيل دخول التاجر مع التحقق الآمن
@app.post("/api/merchants/login")
async def login_merchant(request: Request):
    data = await parse_body(request)
    phone = str(data.get("phone", "")).strip()
    password = str(data.get("password", "")).strip()

    conn = get_db()
    cursor = conn.cursor()
    merchant = cursor.execute("SELECT id, name, shop_name, phone, location, password FROM merchants WHERE phone = ?", (phone,)).fetchone()

    if not merchant:
        conn.close()
        raise HTTPException(status_code=401, detail="بيانات الدخول غير صحيحة")

    m_data = dict(merchant)
    stored_hash = m_data.get("password", "")

    if not verify_password(password, stored_hash):
        conn.close()
        raise HTTPException(status_code=401, detail="بيانات الدخول غير صحيحة")

    if "$" not in stored_hash:
        new_hash = hash_password(password)
        cursor.execute("UPDATE merchants SET password = ? WHERE id = ?", (new_hash, m_data["id"]))
        conn.commit()
    conn.close()

    m_name = m_data.get("name") or m_data.get("shop_name")
    ACTIVE_MERCHANT["id"] = m_data["id"]
    ACTIVE_MERCHANT["phone"] = m_data["phone"]
    ACTIVE_MERCHANT["name"] = m_name

    del m_data["password"]
    res = JSONResponse(content={"status": "success", "authenticated": True, "merchant": m_data, "id": m_data["id"], "phone": m_data["phone"], "name": m_name})
    res.set_cookie("merchant_id", str(m_data["id"]), max_age=86400*30, httponly=True)
    res.set_cookie("merchant_phone", str(m_data["phone"]), max_age=86400*30)
    return res

@app.delete("/api/admin/merchants/{merchant_id}", dependencies=[Depends(require_admin)])
@app.post("/api/admin/merchants/{merchant_id}/delete", dependencies=[Depends(require_admin)])
def delete_admin_merchant(merchant_id: int):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM merchants WHERE id = ?", (merchant_id,))
    cursor.execute("DELETE FROM products WHERE merchant_id = ?", (merchant_id,))
    conn.commit()
    conn.close()
    return {"status": "success", "message": "تم حذف المحل وجميع سلع التاجر بنجاح"}

# رفع السلع عبر الإكسل
@app.post("/api/admin/products/bulk", dependencies=[Depends(require_admin)])
async def bulk_add_products(request: Request):
    data = await parse_body(request)
    merchant_id = to_int(data.get("merchant_id"))
    products_list = data.get("products") or []
    if not products_list or not isinstance(products_list, list):
        raise HTTPException(status_code=400, detail="قائمة المنتجات فارغة")

    conn = get_db()
    cursor = conn.cursor()
    merchant_phone = ""
    if merchant_id:
        m = cursor.execute("SELECT phone FROM merchants WHERE id = ?", (merchant_id,)).fetchone()
        if m:
            merchant_phone = m["phone"]

    inserted_count = 0
    for p in products_list:
        p_name = p.get("name") or p.get("اسم_السلعة") or p.get("الاسم") or "سلعة مستوردة"
        p_price = to_float(p.get("price") or p.get("السعر") or 0.0)
        p_category = p.get("category") or p.get("القسم") or "أخرى"
        p_desc = p.get("description") or p.get("الوصف") or ""
        p_img = p.get("image_url") or p.get("رابط_الصورة") or p.get("الصورة") or ""
        p_stock = to_int(p.get("stock") or p.get("الكمية") or 10)

        cursor.execute("""
            INSERT INTO products (merchant_id, merchant_phone, name, price, description, category, image_url, stock)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (merchant_id, merchant_phone, p_name, p_price, p_desc, p_category, p_img, p_stock))
        inserted_count += 1

    conn.commit()
    conn.close()
    return {"status": "success", "message": f"تم بنجاح رفع واستيراد {inserted_count} سلعة للمتجر!", "count": inserted_count}

# إضافة سلعة كإدارة
@app.post("/api/admin/products/add", dependencies=[Depends(require_admin)])
async def admin_add_single_product(request: Request):
    data = await parse_body(request)
    merchant_id = to_int(data.get("merchant_id"))
    name = data.get("name") or "منتج جديد"
    price = to_float(data.get("price") or 0.0)
    cat = data.get("category") or "عام"
    desc = data.get("description") or ""
    img = data.get("image_url") or ""
    stock = to_int(data.get("stock") or 10)

    conn = get_db()
    cursor = conn.cursor()
    m_phone = ""
    if merchant_id:
        m = cursor.execute("SELECT phone FROM merchants WHERE id = ?", (merchant_id,)).fetchone()
        if m:
            m_phone = m["phone"]

    cursor.execute("""
        INSERT INTO products (merchant_id, merchant_phone, name, price, description, category, image_url, stock)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (merchant_id, m_phone, name, price, desc, cat, img, stock))
    conn.commit()
    p_id = cursor.lastrowid
    conn.close()
    return {"status": "success", "message": "تمت إضافة السلعة بنجاح", "id": p_id}

# رفع وحفظ السلع مع فحص امتداد وحجم الملف الآمن
@app.post("/api/products")
@app.post("/api/merchant/products")
async def add_merchant_product(request: Request):
    content_type = request.headers.get("content-type", "")
    name, price, desc, cat, img, stock = "منتج جديد", 0.0, "", "ملابس وأزياء", "", 10
    body_dict = {}

    if "multipart/form-data" in content_type:
        form = await request.form()
        body_dict = dict(form)
        name = form.get("name") or name
        price = float(form.get("price") or 0)
        desc = form.get("description") or ""
        cat = form.get("category") or cat
        stock = int(form.get("stock") or 10)
        file = form.get("image") or form.get("file")
        if file and hasattr(file, "filename") and file.filename:
            ext = os.path.splitext(file.filename)[1].lower()
            if ext not in ALLOWED_EXTENSIONS:
                raise HTTPException(status_code=400, detail="نوع الملف غير مدعوم، يرجى رفع صورة (jpg, png, webp)")
            
            file_bytes = await file.read()
            if len(file_bytes) > MAX_FILE_SIZE:
                raise HTTPException(status_code=400, detail="حجم الصورة كبير جداً (الحد الأقصى 3 ميجابايت)")
                
            fname = f"{secrets.token_hex(8)}_{int(time.time())}{ext}"
            with open(os.path.join(uploads_dir, fname), "wb") as f:
                f.write(file_bytes)
            img = f"/uploads/{fname}"
        elif form.get("image_url"):
            img = str(form.get("image_url"))
    else:
        body_dict = await parse_body(request)
        name = body_dict.get("name") or name
        price = float(body_dict.get("price") or 0)
        desc = body_dict.get("description") or ""
        cat = body_dict.get("category") or cat
        img = body_dict.get("image_url") or ""
        stock = int(body_dict.get("stock") or 10)

    m_id, m_phone = extract_merchant(request, body_dict)
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO products (merchant_id, merchant_phone, name, price, description, category, image_url, stock)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (m_id, m_phone, name, price, desc, cat, img, stock))
    conn.commit()
    p_id = cursor.lastrowid
    conn.close()
    return {"status": "success", "message": "تمت إضافة السلعة بأمان!", "id": p_id}

# مسار استقبال الطلبات
@app.post("/api/orders")
async def create_order(request: Request):
    data = await parse_body(request)
    c_name = data.get("customer_name") or data.get("name") or "عميل"
    c_phone = data.get("phone") or data.get("customer_phone") or ""
    c_address = data.get("address") or data.get("city") or "حضرموت"
    items_raw = data.get("items")
    total = to_float(data.get("total_price") or data.get("total")) or 0.0
    pay_method = data.get("payment_method") or "الدفع عند الاستلام"
    marketer = str(data.get("marketer_code") or "مباشر").strip().upper()

    items_str = json.dumps(items_raw, ensure_ascii=False) if isinstance(items_raw, (list, dict)) else str(items_raw or "[]")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO orders (customer_name, phone, address, items, total_price, payment_method, marketer_code)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (c_name, c_phone, c_address, items_str, total, pay_method, marketer))
    
    if marketer and marketer != "مباشر":
        cursor.execute("UPDATE marketers SET sales_count = sales_count + 1, total_earnings = total_earnings + ? WHERE code = ?", (total * 0.07, marketer))
        m_row = cursor.execute("SELECT leader_code FROM marketers WHERE code = ?", (marketer,)).fetchone()
        if m_row and m_row["leader_code"]:
            cursor.execute("UPDATE marketers SET total_earnings = total_earnings + ? WHERE code = ?", (total * 0.03, m_row["leader_code"]))
            
    conn.commit()
    order_id = cursor.lastrowid
    conn.close()

    items_lines = []
    if isinstance(items_raw, list):
        for idx, it in enumerate(items_raw, start=1):
            p_name = it.get('name', 'سلعة')
            p_qty = it.get('quantity', 1)
            p_price = to_float(it.get('price')) or 0
            p_shop = it.get('shop_name', 'متجر حضرموت')
            p_img = it.get('image_url', '')
            line = f"{idx}. *{p_name}* (الكمية: {p_qty}) | السعر: {p_price:,.0f} ر.ي\n🏬 المحل: {p_shop}"
            if p_img:
                line += f"\n🖼️ الصورة: {p_img}"
            items_lines.append(line)
    
    items_formatted = "\n\n".join(items_lines) if items_lines else "لا توجد تفاصيل أصناف"

    wa_text = (
        f"🛒 *طلب شراء جديد من متجر حضرموت (سلة تسوق)*\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"🏷️ *رقم الطلب:* #{order_id}\n"
        f"👤 *المشتري:* {c_name}\n"
        f"📱 *الهاتف:* {c_phone}\n"
        f"📍 *موقع الاستلام:* {c_address}\n"
        f"💳 *طريقة الدفع:* {pay_method}\n"
        f"🏷️ *كود المسوق:* {marketer}\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"📦 *قائمة السلع المطلوبة:*\n\n{items_formatted}\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"💰 *الإجمالي المستحق:* {total:,.0f} ريال يمني\n"
        f"يرجى تأكيد تجهيز الشحنة وتوجيه المندوب. 🚚"
    )

    wa_url = f"https://wa.me/{MY_WHATSAPP_PHONE}?text={urllib.parse.quote(wa_text)}"

    return {
        "status": "success",
        "success": True,
        "ok": True,
        "message": "تم استلام الطلب بنجاح!",
        "order_id": order_id,
        "whatsapp_url": wa_url,
        "invoice_url": f"/api/orders/{order_id}/invoice"
    }

@app.get("/api/orders")
@app.get("/api/admin/orders")
def get_orders():
    conn = get_db()
    cursor = conn.cursor()
    rows = [dict(r) for r in cursor.execute("SELECT * FROM orders ORDER BY id DESC").fetchall()]
    conn.close()
    return rows

@app.get("/api/orders/{order_id}/invoice", response_class=HTMLResponse)
def get_order_invoice(order_id: int):
    conn = get_db()
    cursor = conn.cursor()
    order = cursor.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    conn.close()

    if not order:
        return HTMLResponse("<h3>الفاتورة غير موجودة</h3>", status_code=404)

    o = dict(order)
    try:
        items = json.loads(o.get("items", "[]"))
    except Exception:
        items = []

    rows_html = ""
    for idx, it in enumerate(items, start=1):
        name = it.get("name", "سلعة")
        shop = it.get("shop_name", "متجر معتمد")
        qty = it.get("quantity", 1)
        price = to_float(it.get("price")) or 0
        subtotal = qty * price
        rows_html += f"""
        <tr>
            <td style="padding: 10px; border: 1px solid #ddd; text-align: center;">{idx}</td>
            <td style="padding: 10px; border: 1px solid #ddd;"><b>{name}</b><br><small style="color: #666;">المحل: {shop}</small></td>
            <td style="padding: 10px; border: 1px solid #ddd; text-align: center;">{price:,.0f} ر.ي</td>
            <td style="padding: 10px; border: 1px solid #ddd; text-align: center;">{qty}</td>
            <td style="padding: 10px; border: 1px solid #ddd; text-align: center; font-weight: bold; color: #b8860b;">{subtotal:,.0f} ر.ي</td>
        </tr>
        """

    invoice_html = f"""
    <!DOCTYPE html>
    <html lang="ar" dir="rtl">
    <head>
        <meta charset="UTF-8">
        <title>فاتورة شراء رقم #{o['id']} | متجر حضرموت الذكي</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, sans-serif; background: #f4f6f9; color: #333; padding: 20px; }}
            .invoice-card {{ max-width: 800px; margin: auto; background: #fff; padding: 30px; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); border-top: 6px solid #d4af37; }}
            .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #eee; padding-bottom: 15px; margin-bottom: 20px; }}
            .title {{ color: #b8860b; font-size: 24px; font-weight: bold; }}
            .info-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin-bottom: 20px; background: #fafafa; padding: 15px; border-radius: 8px; }}
            table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
            th {{ background: #111317; color: #d4af37; padding: 12px; border: 1px solid #ddd; }}
            .total-box {{ text-align: left; font-size: 20px; font-weight: bold; color: #b8860b; margin-top: 15px; }}
            .print-btn {{ background: #d4af37; color: #000; border: none; padding: 10px 25px; font-size: 16px; font-weight: bold; border-radius: 6px; cursor: pointer; }}
            @media print {{ .no-print {{ display: none; }} body {{ padding: 0; background: #fff; }} .invoice-card {{ box-shadow: none; border: none; }} }}
        </style>
    </head>
    <body>
        <div class="invoice-card">
            <div class="header">
                <div>
                    <div class="title">👑 متجر حضرموت الذكي</div>
                    <small>فاتورة طلب إلكتروني رسمي</small>
                </div>
                <div style="text-align: left;">
                    <div><b>رقم الفاتورة:</b> #{o['id']}</div>
                    <div><b>التاريخ:</b> {str(o.get('created_at', ''))[:16]}</div>
                </div>
            </div>

            <div class="info-grid">
                <div><b>اسم العميل:</b> {o['customer_name']}</div>
                <div><b>رقم الهاتف:</b> {o['phone']}</div>
                <div><b>عنوان التوصيل:</b> {o['address']}</div>
                <div><b>طريقة الدفع:</b> {o['payment_method']}</div>
            </div>

            <table>
                <thead>
                    <tr>
                        <th>#</th>
                        <th>السلعة / البيان</th>
                        <th>السعر الفردي</th>
                        <th>الكمية</th>
                        <th>الإجمالي</th>
                    </tr>
                </thead>
                <tbody>
                    {rows_html}
                </tbody>
            </table>

            <div class="total-box">
                الإجمالي الكلي المستحق: {to_float(o['total_price']):,.0f} ريال يمني
            </div>

            <hr style="margin-top: 30px; border-color: #eee;">
            <div style="display: flex; justify-content: space-between; align-items: center;" class="no-print">
                <button class="print-btn" onclick="window.print()">🖨️ طباعة الفاتورة / حفظ كـ PDF</button>
                <small style="color: #888;">شكراً لتسوقكم معنا في متجر حضرموت</small>
            </div>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(invoice_html)

# مسارات الحذف وتعديل السعر وسلع التجار
@app.api_route("/api/products/delete", methods=["GET", "POST", "DELETE"])
@app.api_route("/api/merchant/products/delete", methods=["GET", "POST", "DELETE"])
@app.api_route("/api/products/{product_id}/delete", methods=["GET", "POST", "DELETE"])
@app.api_route("/api/merchant/products/{product_id}/delete", methods=["GET", "POST", "DELETE"])
@app.delete("/api/products/{product_id}")
@app.delete("/api/merchant/products/{product_id}")
async def delete_product_handler(request: Request, product_id: Optional[str] = None):
    data = await parse_body(request)
    qp = request.query_params
    p_id = to_int(product_id) or to_int(data.get("id")) or to_int(data.get("product_id")) or to_int(qp.get("id"))
    if p_id:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM products WHERE id = ?", (p_id,))
        conn.commit()
        conn.close()
    return {"status": "success", "success": True, "ok": True, "message": "تم حذف السلعة بنجاح!"}

@app.api_route("/api/products/update-price", methods=["POST", "PUT", "PATCH"])
@app.api_route("/api/merchant/products/update-price", methods=["POST", "PUT", "PATCH"])
@app.api_route("/api/products/{product_id}/update-price", methods=["POST", "PUT", "PATCH"])
@app.put("/api/products/{product_id}")
async def update_price_handler(request: Request, product_id: Optional[str] = None):
    data = await parse_body(request)
    qp = request.query_params
    p_id = to_int(product_id) or to_int(data.get("id")) or to_int(data.get("product_id")) or to_int(qp.get("id"))
    price = to_float(data.get("price")) or to_float(data.get("new_price")) or to_float(qp.get("price"))
    name = data.get("name")
    if p_id and price is not None:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("UPDATE products SET price = ? WHERE id = ?", (price, p_id))
        if name:
            cursor.execute("UPDATE products SET name = ? WHERE id = ?", (str(name), p_id))
        conn.commit()
        conn.close()
    return {"status": "success", "success": True, "ok": True, "message": "تم تعديل السعر بنجاح!"}

@app.get("/api/merchant/my-products")
def get_my_merchant_products(request: Request):
    m_id, m_phone = extract_merchant(request)
    conn = get_db()
    cursor = conn.cursor()
    if m_id:
        cursor.execute("UPDATE products SET merchant_id = ?, merchant_phone = ? WHERE merchant_id IS NULL OR merchant_id = 0", (m_id, m_phone))
        conn.commit()
        cursor.execute("SELECT * FROM products WHERE merchant_id = ? OR merchant_phone = ? ORDER BY id DESC", (m_id, m_phone))
    else:
        cursor.execute("SELECT * FROM products ORDER BY id DESC")
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows

@app.get("/api/products")
@app.get("/api/admin/products")
def get_public_products():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT p.*, COALESCE(m.shop_name, m.name, 'متجر عام') as shop_name 
        FROM products p 
        LEFT JOIN merchants m ON p.merchant_id = m.id OR p.merchant_phone = m.phone 
        ORDER BY p.id DESC
    """)
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows

@app.get("/", response_class=FileResponse)
async def serve_home():
    return FileResponse(os.path.join(BASE_DIR, "index.html"))

@app.get("/admin", response_class=FileResponse)
async def serve_admin():
    return FileResponse(os.path.join(BASE_DIR, "admin.html"))

@app.get("/merchant", response_class=FileResponse)
async def serve_merchant():
    return FileResponse(os.path.join(BASE_DIR, "merchant.html"))

if __name__ == "__main__":
    target_port = int(os.getenv("PORT", "8080"))
    uvicorn.run("main:app", host="0.0.0.0", port=target_port, reload=False, workers=1, access_log=False)