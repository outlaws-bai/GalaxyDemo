import os
import json
from ciphers import get_cipher_map, reandom_str
from ciphers.dynamic_key import DynamicKey
from fastapi import FastAPI, Body, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse

# uvicorn manager:app --host 0.0.0.0 --reload
app = FastAPI()
cipher_map = get_cipher_map()


users_db = {
    "user1": {"id": 1, "name": "Alice", "email": "alice@example.com"},
    "user2": {"id": 2, "name": "Bob", "email": "bob@example.com"},
}


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
    if not username or username not in users_db:
        raise HTTPException(status_code=404, detail="User not found")
    user_info = users_db[username]
    print(f"response data : {user_info}")
    # 加密响应
    return JSONResponse(cipher.encrypt(user_info))


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
