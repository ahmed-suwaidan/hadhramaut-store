import os
import shutil
import zipfile
from datetime import datetime

# المسارات
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, "database.db")
UPLOADS_DIR = os.path.join(BASE_DIR, "uploads")
BACKUP_DIR = os.path.join(BASE_DIR, "backups")

# إنشاء مجلد النسخ الاحتياطية إن لم يكن موجوداً
os.makedirs(BACKUP_DIR, exist_ok=True)

# اسم ملف النسخة الاحتياطية مدمجاً به تاريخ ولحظة النسخ
timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
zip_filename = os.path.join(BACKUP_DIR, f"backup_{timestamp}.zip")

print(f"[*] بدء عملية النسخ الاحتياطي: {timestamp}")

# إنشاء الملف المضغوط
with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
    # 1. نسخ قاعدة البيانات
    if os.path.exists(DB_FILE):
        zipf.write(DB_FILE, arcname="database.db")
        print("[+] تم نسخ قاعدة البيانات بنجاح.")

    # 2. نسخ مجلد الصور
    if os.path.exists(UPLOADS_DIR):
        for root, dirs, files in os.walk(UPLOADS_DIR):
            for file in files:
                file_path = os.path.join(root, file)
                arcname = os.path.relpath(file_path, BASE_DIR)
                zipf.write(file_path, arcname=arcname)
        print("[+] تم نسخ مجلد الصور المرفوعة بنجاح.")

print(f"[✓] اكتمل النسخ الاحتياطي بنجاح في: {zip_filename}")