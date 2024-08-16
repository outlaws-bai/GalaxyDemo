import sqlite3
import traceback
from ciphers import get_cipher_map
from fastapi import FastAPI, Body, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse

# uvicorn manager:app --host 0.0.0.0 --reload
app = FastAPI()
cipher_map = get_cipher_map()


# 创建 SQLite 数据库引擎
DATABASE_URL = "./user.db"
# users = [
#         {"id": 1, "name": "user1", "email": "alice@example.com"},
#         {"id": 2, "name": "user2", "email": "bob@example.com"},
#     ]


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
    conn = sqlite3.connect(DATABASE_URL)
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE name = '{username}'"
    try:
        cursor.execute(query)
        result = cursor.fetchone()
        if result is None:
            raise HTTPException(status_code=404, detail="User not found")
        user_info = {"id": result[0], "name": result[1], "email": result[2]}
    except Exception:
        user_info = {"status": "fail", "message": traceback.format_exc()}
    print(f"response data : {user_info}")
    # 加密响应
    return JSONResponse(cipher.encrypt(user_info))


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
