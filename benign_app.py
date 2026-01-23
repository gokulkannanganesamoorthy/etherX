from fastapi import FastAPI, Request
import uvicorn
import random

app = FastAPI()

@app.get("/")
async def home():
    return {"message": "Welcome to Benign App"}

@app.api_route("/login", methods=["GET", "POST"])
async def login(request: Request):
    if request.method == "POST":
        return {"status": "success", "token": "abc123xyz"}
    return {"message": "Login Page"}

@app.get("/products")
async def products():
    return {"products": [{"id": i, "name": f"Item {i}"} for i in range(10)]}

@app.post("/api/feedbacks")
async def feedback():
    return {"status": "received"}

@app.get("/search")
async def search(q: str = ""):
    return {"results": [f"Result for {q}"]}

# JuiceShop routes for compatibility
@app.get("/rest/products/search")
async def product_search(q: str = ""):
    return {"data": [{"name": f"{q} product"}]}

@app.get("/api/Users")
async def users():
    return {"users": []}

@app.get("/api/Products")
async def api_products():
    return {"data": []}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=3000)
