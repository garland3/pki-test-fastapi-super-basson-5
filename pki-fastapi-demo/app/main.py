from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
import time
import re

app=FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")

def _cn_from_dn(dn:str|None)->str|None:
    if not dn: return None
    m=re.search(r"CN=([^,]+)",dn)
    return m.group(1) if m else None

def _cert_info(req:Request):
    v=req.headers.get("x-ssl-client-verify","").upper()
    if v!="SUCCESS": raise HTTPException(401,"Client certificate required/invalid")
    sdn=req.headers.get("x-ssl-client-s-dn")
    return {
        "verified":True,
        "subject_dn":sdn,
        "issuer_dn":req.headers.get("x-ssl-client-i-dn"),
        "serial":req.headers.get("x-ssl-client-serial"),
        "fingerprint":req.headers.get("x-ssl-client-fingerprint"),
        "common_name":_cn_from_dn(sdn)
    }

@app.get("/", response_class=HTMLResponse)
def home():
    # Serve the static UI; the page calls /api endpoints via fetch()
    return FileResponse("static/index.html")

@app.get("/me")
def me(req:Request): return JSONResponse(_cert_info(req))

@app.get("/api/me")
def api_me(req: Request):
    return JSONResponse(_cert_info(req))

@app.get("/health")
def health(): return {"ok":True}

@app.get("/api/health")
def api_health(): return {"ok": True}

# --- Request logging middleware ---
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = time.perf_counter()
    method = request.method
    path = request.url.path
    route_tmpl = None
    route = request.scope.get("route")
    if route is not None:
        route_tmpl = getattr(route, "path", None) or getattr(route, "path_format", None)
    try:
        response = await call_next(request)
        status = response.status_code
    except Exception:
        status = 500
        raise
    finally:
        dur_ms = (time.perf_counter() - start) * 1000
        print(f"[REQ] {method} {path} -> {status} route={route_tmpl or '-'} {dur_ms:.1f}ms")
    return response


@app.get("/api/protected")
def api_protected(req: Request):
    # Validate client cert (raises 401 if invalid/missing)
    info = _cert_info(req)
    user = info.get("common_name") or info.get("subject_dn") or "Unknown"
    # Print authenticated user server-side
    print(
        "[AUTH] user=%s serial=%s issuer=%s subject=%s" % (
            user,
            info.get("serial"),
            info.get("issuer_dn"),
            info.get("subject_dn"),
        )
    )
    return {"ok": True, "message": f"Hello, {user}", "identity": info}


@app.get("/protected", response_class=HTMLResponse)
def protected():
    return FileResponse("static/protected.html")
