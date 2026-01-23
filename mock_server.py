from fastapi import FastAPI, Request
import uvicorn

app = FastAPI()

@app.api_route("/{path_name:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
async def catch_all(path_name: str, request: Request):
    return {
        "status": "success",
        "service": "Upstream App (Mock)",
        "received_path": path_name,
        "method": request.method
    }

if __name__ == "__main__":
    print("Starting Mock Upstream Server on Port 3000...")
    uvicorn.run(app, host="0.0.0.0", port=3000, log_level="error")
