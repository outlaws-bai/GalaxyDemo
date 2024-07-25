import os
import json
import typing as t
from ciphers import get_cipher_map, reandom_str
from ciphers.dynamic_key import DynamicKey
from fastapi import FastAPI, Body, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse

# uvicorn manager:app --host 0.0.0.0 --reload
app = FastAPI()
cipher_map = get_cipher_map()


def generate_index_html():
    html_files = [f for f in os.listdir("statics") if f.endswith(".html")]
    links = "\n".join(
        [
            f'<li><a href="/{file}">{file}</a></li>'
            for file in html_files
            if not file.startswith("Index")
        ]
    )
    index_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Index</title>
    </head>
    <body>
        <h1>Index of HTML Files</h1>
        <ul>
            {links}
        </ul>
    </body>
    </html>
    """
    with open(os.path.join("statics", "Index.html"), "w") as f:
        f.write(index_content)


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


@app.get("/api/getSecret")
async def get_secret():
    key = reandom_str(32)
    iv = reandom_str(16)
    DynamicKey.key = key
    DynamicKey.iv = iv
    return {"key": key, "iv": iv}


@app.post("/api/{cipher_name}/getUserInfo", response_class=JSONResponse)
async def get_user_info(cipher_name, json_body: dict[str, t.Any] = Body(...)):
    # 解密请求
    cipher = cipher_map[cipher_name]
    row_data = cipher.decrypt(json_body)
    print(f"decryptde data: {row_data}")
    # 业务逻辑
    username = row_data.get("username")
    if not username or username not in users_db:
        raise HTTPException(status_code=404, detail="User not found")
    user_info = users_db[username]
    print(f"response data : {user_info}")
    # 加密响应
    return JSONResponse(cipher.encrypt(user_info))


if __name__ == "__main__":
    generate_index_html()
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
