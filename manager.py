import os
import json
from jinja2 import Template
from ciphers import get_cipher_map
from pathlib import Path
from fastapi import FastAPI, Body, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql import text

# uvicorn manager:app --host 0.0.0.0 --reload
app = FastAPI()
cipher_map = get_cipher_map()


# 创建 SQLite 数据库引擎
DATABASE_URL = "sqlite:///./user.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

# 创建 Base 类用于定义模型
Base = declarative_base()

# 创建数据库会话
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


# 定义 User 模型
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    email = Column(String, unique=True, index=True)

    def to_json(self):
        return {"id": self.id, "name": self.name, "email": self.email}


@app.on_event("startup")
def startup_event():
    # 创建表
    db = SessionLocal()
    if Path("./user.db").exists():
        for user in db.query(User).all():
            print(user.to_json())
        return
    Base.metadata.create_all(bind=engine)

    users = [
        {"id": 1, "name": "user1", "email": "alice@example.com"},
        {"id": 2, "name": "user2", "email": "bob@example.com"},
    ]
    for user_data in users:
        user = User(
            id=user_data["id"], name=user_data["name"], email=user_data["email"]
        )
        db.add(user)
    db.commit()
    for user in db.query(User).all():
        print(user.to_json())


@app.get("/", response_class=HTMLResponse)
async def read_index():
    return RedirectResponse("/Index.html")


@app.get("/{name}.html", response_class=HTMLResponse)
async def render_html(name):
    with open(f"statics/{name}.html", encoding="utf-8") as f:
        return HTMLResponse(content=f.read(), status_code=200)


@app.post("/api/{cipher_name}/getUserInfo", response_class=JSONResponse)
async def get_user_info(cipher_name, json_body=Body(...)):
    # 解密请求
    cipher = cipher_map[cipher_name]
    row_data = cipher.decrypt(json_body)
    print(f"decryptde data: {row_data}")
    # 业务逻辑
    username = row_data.get("username")  # type: ignore
    if not username:
        raise HTTPException(status_code=404, detail="User not found")
    db = SessionLocal()
    query = f"SELECT * FROM users WHERE name = '{username}'"
    conn = db.connection()
    result = conn.execute(text(query)).fetchone()
    if result is None:
        raise HTTPException(status_code=404, detail="User not found")
    user_info = {"id": result[0], "name": result[1], "email": result[2]}
    print(f"response data : {user_info}")
    # 加密响应
    return JSONResponse(cipher.encrypt(user_info))


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
