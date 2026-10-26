"""SafeZone AI backend: FastAPI + SQLite + prototype risk indicator + optional Gemini."""
import os, json, math, sqlite3, uuid, html, time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Literal
import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Header, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")
DB = Path(os.getenv("DB_PATH", str(ROOT / "safezone.db")))
SEV = {"low": 1, "medium": 2, "high": 3}
app = FastAPI(title="SafeZone AI")
app.add_middleware(CORSMiddleware, allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:8000").split(","),
                   allow_methods=["*"], allow_headers=["*"])

HITS = {}
def limit(req: Request, name: str, n: int, per: int = 60):
    """Simple per-IP rate limit (in memory). Use --proxy-headers behind a host so IPs are real."""
    k = (name, req.client.host if req.client else "?"); t = time.time()
    q = [x for x in HITS.get(k, []) if t - x < per]
    if len(q) >= n: raise HTTPException(429, "Too many requests. Please try again in a minute.")
    q.append(t); HITS[k] = q

def db():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row; return c

with db() as c:
    c.execute("""CREATE TABLE IF NOT EXISTS hazards(id TEXT PRIMARY KEY, type TEXT, lat REAL, lon REAL,
      description TEXT, severity TEXT, observed_at TEXT, source TEXT, verification TEXT DEFAULT 'unverified',
      flags INTEGER DEFAULT 0, created_at TEXT)""")

def now(): return datetime.now(timezone.utc).isoformat()

def dist_m(a, b, c, d):
    p = math.pi / 180
    h = math.sin((c - a) * p / 2) ** 2 + math.cos(a * p) * math.cos(c * p) * math.sin((d - b) * p / 2) ** 2
    return 12742000 * math.asin(math.sqrt(h))

def risk(p):
    """Prototype Risk Indicator 0-100. NOT validated. Severity 50%, verification 30%, recency 20%; flags subtract."""
    s = SEV.get(p["severity"], 1) / 3 * 50
    v = {"verified": 30, "unverified": 8}.get(p["verification"], 0)
    try:
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(p["observed_at"].replace("Z", "+00:00"))).days
    except Exception:
        age = 365
    r = 20 * max(0.0, 1 - age / 30)
    return round(max(0, s + v + r - 5 * p.get("flags", 0)))

def feature(row):
    p = {k: row[k] for k in ("id", "type", "severity", "description", "observed_at", "source", "verification")}
    p["flags"] = row.get("flags", 0); p["demo"] = row.get("demo", False)
    p["risk_indicator"] = risk(p)
    return {"type": "Feature", "geometry": row["geometry"], "properties": p}

def all_features():
    out = []
    demo = json.loads((ROOT / "data" / "demo_hazards.geojson").read_text(encoding="utf-8"))
    for f in demo["features"]:
        out.append({**f["properties"], "geometry": f["geometry"]})
    with db() as c:
        for r in c.execute("SELECT * FROM hazards WHERE verification NOT IN ('rejected','archived')"):
            d = dict(r); d["geometry"] = {"type": "Point", "coordinates": [d["lon"], d["lat"]]}; d["demo"] = False
            out.append(d)
    return out

def centre(g):
    if g["type"] == "Point": return g["coordinates"][1], g["coordinates"][0]
    ring = g["coordinates"][0]; return sum(p[1] for p in ring) / len(ring), sum(p[0] for p in ring) / len(ring)

class Report(BaseModel):
    type: Literal["accident", "crime", "flood", "fire", "construction", "other"]
    lat: float = Field(ge=-90, le=90); lon: float = Field(ge=-180, le=180)
    description: str = Field(min_length=5, max_length=500)
    severity: Literal["low", "medium", "high"]
    observed_at: str
    source: str = Field(default="User report", max_length=200)

@app.get("/api/health")
def health(): return {"status": "ok", "ai_configured": bool(os.getenv("GEMINI_API_KEY"))}

@app.get("/api/hazards")
def hazards(type: Optional[str] = None, severity: Optional[str] = None, verification: Optional[str] = None):
    fs = [f for f in all_features() if (not type or f["type"] == type) and (not severity or f["severity"] == severity)
          and (not verification or f["verification"] == verification)]
    return {"type": "FeatureCollection", "features": [feature(f) for f in fs]}

@app.get("/api/hazards/nearby")
def nearby(lat: float, lon: float, radius: float = Query(2000, le=50000)):
    res = []
    for f in all_features():
        la, lo = centre(f["geometry"]); d = dist_m(lat, lon, la, lo)
        if d <= radius: ft = feature(f); ft["properties"]["distance_m"] = round(d); res.append(ft)
    res.sort(key=lambda x: x["properties"]["distance_m"])
    return {"type": "FeatureCollection", "features": res}

@app.get("/api/hazards/{hid}")
def one(hid: str):
    for f in all_features():
        if f["id"] == hid: return feature(f)
    raise HTTPException(404, "Hazard not found")

@app.post("/api/hazards", status_code=201)
def submit(req: Request, r: Report):
    limit(req, "submit", 5)
    desc, src = html.escape(r.description.strip()), html.escape(r.source.strip())
    with db() as c:
        for x in c.execute("SELECT lat,lon FROM hazards WHERE type=? AND verification!='rejected'", (r.type,)):
            if dist_m(r.lat, r.lon, x["lat"], x["lon"]) < 50:
                raise HTTPException(409, "A similar report already exists within 50 m. Flag it instead.")
        hid = uuid.uuid4().hex[:10]
        c.execute("INSERT INTO hazards(id,type,lat,lon,description,severity,observed_at,source,verification,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                  (hid, r.type, r.lat, r.lon, desc, r.severity, r.observed_at, src, "unverified", now()))
    return {"id": hid, "verification": "unverified"}

@app.post("/api/reports/{hid}/flag")
def flag(req: Request, hid: str):
    limit(req, "flag", 10)
    with db() as c:
        if c.execute("UPDATE hazards SET flags=flags+1 WHERE id=?", (hid,)).rowcount == 0:
            raise HTTPException(404, "Only user reports can be flagged")
    return {"flagged": True}

class Review(BaseModel):
    verification: Literal["verified", "unverified", "rejected", "archived"]

@app.patch("/api/admin/hazards/{hid}")
def review(hid: str, r: Review, x_admin_token: str = Header(default="")):
    tok = os.getenv("ADMIN_TOKEN", "")
    if not tok or x_admin_token != tok: raise HTTPException(401, "Admin token required")
    with db() as c:
        if c.execute("UPDATE hazards SET verification=? WHERE id=?", (r.verification, hid)).rowcount == 0:
            raise HTTPException(404, "Not found")
    return {"id": hid, "verification": r.verification}

class Analyze(BaseModel):
    lat: float; lon: float; radius: float = 2000

KEYS = ["hazard_types", "main_evidence", "possible_risks", "severity_assessment", "data_freshness",
        "recommended_precautions", "uncertainties", "follow_up", "verified_info", "unverified_reports"]

CACHE = {}

@app.post("/api/analyze")
async def analyze(req: Request, a: Analyze):
    limit(req, "analyze", 10)
    near = nearby(a.lat, a.lon, a.radius)["features"][:8]
    recs = [{k: f["properties"].get(k) for k in ("type", "severity", "description", "observed_at", "source", "verification", "demo")} for f in near]
    if not recs: return {"ai": False, "summary": "Insufficient data to assess risk.", "note": "No reports is not evidence of safety."}
    key = os.getenv("GEMINI_API_KEY")
    if not key: return {"ai": False, "summary": "AI not configured (no API key). Showing prototype risk indicators only."}
    ck = json.dumps(recs, sort_keys=True)
    hit = CACHE.get(ck)
    if hit and time.time() - hit[0] < 300: return hit[1]
    prompt = ("Using ONLY these hazard records, return JSON with exactly these keys: " + ", ".join(KEYS) +
              ". Each value is ONE short sentence (max 25 words). Separate verified info from unverified reports. Never invent facts. "
              "Do not infer crime from demographics. If evidence is thin say 'Insufficient data to assess risk.'\nRECORDS:\n" + json.dumps(recs))
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{os.getenv('GEMINI_MODEL', 'gemini-2.5-flash')}:generateContent"
    gen = {"responseMimeType": "application/json", "maxOutputTokens": 2000, "thinkingConfig": {"thinkingLevel": "low"}}
    try:
        async with httpx.AsyncClient(timeout=20) as cl:
            r = await cl.post(url, headers={"x-goog-api-key": key}, json={"contents": [{"parts": [{"text": prompt}]}], "generationConfig": gen})
            if r.status_code == 400:
                gen.pop("thinkingConfig")
                r = await cl.post(url, headers={"x-goog-api-key": key}, json={"contents": [{"parts": [{"text": prompt}]}], "generationConfig": gen})
            r.raise_for_status()
        data = json.loads(r.json()["candidates"][0]["content"]["parts"][0]["text"])
        if not isinstance(data, dict) or not all(k in data for k in KEYS): raise ValueError("bad shape")
        out = {"ai": True, "label": "AI-generated, not verified fact", "analysis": data}
        CACHE[ck] = (time.time(), out)
        return out
    except Exception as e:
        return {"ai": False, "summary": "AI analysis unavailable right now. Map and reporting still work.", "error": type(e).__name__}

UA = {"User-Agent": "SafeZoneAI-hackathon/1.0 (local demo)"}

@app.get("/api/geocode")
async def geocode(req: Request, q: str = Query(min_length=2, max_length=120)):
    limit(req, "geocode", 20)
    async with httpx.AsyncClient(timeout=10, headers=UA) as cl:
        try:
            r = await cl.get("https://nominatim.openstreetmap.org/search", params={"format": "json", "limit": 1, "q": q})
            r.raise_for_status(); j = r.json()
            if j: return {"lat": float(j[0]["lat"]), "lon": float(j[0]["lon"]), "name": j[0]["display_name"]}
        except Exception:
            pass
        try:
            r = await cl.get("https://photon.komoot.io/api/", params={"limit": 1, "q": q})
            r.raise_for_status(); f = r.json().get("features", [])
            if f:
                c = f[0]["geometry"]["coordinates"]; p = f[0]["properties"]
                return {"lat": c[1], "lon": c[0], "name": ", ".join(x for x in (p.get("name"), p.get("country")) if x)}
        except Exception:
            raise HTTPException(502, "Geocoding services unreachable")
    raise HTTPException(404, "No match")

@app.get("/api/route")
async def route(req: Request, coords: str = Query(pattern=r"^-?\d+(\.\d+)?,-?\d+(\.\d+)?(;-?\d+(\.\d+)?,-?\d+(\.\d+)?){1,5}$")):
    limit(req, "route", 10)
    try:
        async with httpx.AsyncClient(timeout=15, headers=UA) as cl:
            r = await cl.get(f"https://router.project-osrm.org/route/v1/driving/{coords}", params={"overview": "full", "geometries": "geojson"})
            r.raise_for_status(); j = r.json()
        if j.get("code") != "Ok": raise ValueError("no route")
        return {"coordinates": j["routes"][0]["geometry"]["coordinates"]}
    except Exception:
        raise HTTPException(502, "Routing unavailable")

@app.get("/api/config")
def config(): return {"google_maps_key": os.getenv("GOOGLE_MAPS_API_KEY", "")}

app.mount("/", StaticFiles(directory=ROOT / "web", html=True), name="static")
