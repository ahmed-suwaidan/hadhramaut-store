import os
import sqlite3
import shutil
from typing import Optional
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
DB_PATH = os.path.join(BASE_DIR, "store.db")

# إنشاء مجلد حفظ الصور المرفوعة تلقائياً
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = FastAPI(title="متجر حضرموت الذكي")

# السماح بالاتصال من أي مصدر
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ربط مجلد الصور
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")

# --- تهيئة وتأسيس قاعدة البيانات ---
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # جدول المنتجات
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            price REAL NOT NULL,
            category TEXT NOT NULL,
            image TEXT,
            description TEXT,
            merchant_name TEXT DEFAULT 'متجر حضرموت العام'
        )
    """)
    
    # جدول الطلبات
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_name TEXT NOT NULL,
            customer_phone TEXT NOT NULL,
            city TEXT NOT NULL,
            payment_method TEXT NOT NULL,
            items_json TEXT NOT NULL,
            total_price REAL NOT NULL,
            status TEXT DEFAULT 'معلق',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # بذر بيانات أولية للمنتجات عند تشغيل التطبيق لأول مرة
    cursor.execute("SELECT COUNT(*) FROM products")
    if cursor.fetchone()[0] == 0:
        sample_products = [
            ("عسل سدر دوعني ملكي فاخر", 28000, "منتجات محلية", "https://images.unsplash.com/photo-1587049352846-4a222e784d38?w=500", "عسل سدر طبيعي 100% مستخرج من مناحل وادي دوعن.", "مناحل وادي دوعن"),
            ("بخور وعود حضرمي عرايسي", 12000, "عطور وبخور", "https://images.unsplash.com/photo-1592945403244-b3fbafd7f539?w=500", "خلطة بخور ملكية بثبات عالي ورائحة أصيلة.", "دار الطيب الحضرمي"),
            ("بن يمني حرازي أصيل (درجة أولى)", 7500, "منتجات محلية", "https://images.unsplash.com/photo-1514432324607-a09d9b4aefdd?w=500", "بن محمص ومطحون بعناية للقهوة العربية الأصيلة.", "محامص الأصالة"),
            ("ساعة يد كلاسيكية رجالية", 19500, "إلكترونيات وساعات", "https://images.unsplash.com/photo-1524805444758-089113d48a6d?w=500", "ساعة يد كلاسيكية مقاومة للماء مع حزام جلدي أنيق.", "أناقة حضرموت")
        ]
        cursor.executemany(
            "INSERT INTO products (name, price, category, image, description, merchant_name) VALUES (?, ?, ?, ?, ?, ?)",
            sample_products
        )
        conn.commit()
        
    conn.close()

init_db()

# --- مسارات الصفحات الثابتة وملفات الـ PWA ---
@app.get("/", response_class=HTMLResponse)
async def serve_index():
    return FileResponse(os.path.join(BASE_DIR, "index.html"))

@app.get("/admin", response_class=HTMLResponse)
async def serve_admin():
    return FileResponse(os.path.join(BASE_DIR, "admin.html"))

@app.get("/merchant", response_class=HTMLResponse)
async def serve_merchant():
    return FileResponse(os.path.join(BASE_DIR, "merchant.html"))

@app.get("/manifest.json")
async def serve_manifest():
    return FileResponse(os.path.join(BASE_DIR, "manifest.json"), media_type="application/json")

@app.get("/sw.js")
async def serve_sw():
    return FileResponse(os.path.join(BASE_DIR, "sw.js"), media_type="application/javascript")

# --- نماذج وواجهات الـ API ---
class OrderSchema(BaseModel):
    customer_name: str
    customer_phone: str
    city: str
    payment_method: str
    items_json: str
    total_price: float

@app.get("/api/products")
async def get_products():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products ORDER BY id DESC")
    products = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return products

@app.post("/api/products")
async def add_product(
    name: str = Form(...),
    price: float = Form(...),
    category: str = Form(...),
    description: str = Form(""),
    merchant_name: str = Form("متجر حضرموت العام"),
    image_url: Optional[str] = Form(None),
    image_file: Optional[UploadFile] = File(None)
):
    final_image = image_url if image_url else "https://images.unsplash.com/photo-1524805444758-089113d48a6d?w=500"
    
    if image_file and image_file.filename:
        file_location = os.path.join(UPLOAD_DIR, image_file.filename)
        with open(file_location, "wb") as buffer:
            shutil.copyfileobj(image_file.file, buffer)
        final_image = f"/uploads/{image_file.filename}"

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO products (name, price, category, image, description, merchant_name) VALUES (?, ?, ?, ?, ?, ?)",
        (name, price, category, final_image, description, merchant_name)
    )
    conn.commit()
    new_id = cursor.lastrowid
    conn.close()
    return {"status": "success", "product_id": new_id}

@app.delete("/api/products/{product_id}")
async def delete_product(product_id: int):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM products WHERE id = ?", (product_id,))
    conn.commit()
    conn.close()
    return {"status": "deleted"}

@app.get("/api/orders")
async def get_orders():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM orders ORDER BY id DESC")
    orders = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return orders

@app.post("/api/orders")
async def create_order(order: OrderSchema):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO orders (customer_name, customer_phone, city, payment_method, items_json, total_price)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (order.customer_name, order.customer_phone, order.city, order.payment_method, order.items_json, order.total_price))
    conn.commit()
    order_id = cursor.lastrowid
    conn.close()
    return {"status": "success", "order_id": order_id}

@app.put("/api/orders/{order_id}/status")
async def update_order_status(order_id: int, status: str = Form(...)):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("UPDATE orders SET status = ? WHERE id = ?", (status, order_id))
    conn.commit()
    conn.close()
    return {"status": "updated"}

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8080))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)
