import os
import re
import secrets
import hashlib
import hmac
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse
from html import escape

import httpx
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from sqlalchemy import (
    create_engine, Column, Integer, String, Boolean,
    DateTime, ForeignKey, Text, func
)
from sqlalchemy.orm import declarative_base, sessionmaker
from starlette.middleware.sessions import SessionMiddleware


# =========================================================
# CONFIGURATION
# =========================================================

APP_NAME = "KRUTIK CYBER DEVELOPER"

ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
SESSION_SECRET = os.getenv("SESSION_SECRET", "")

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./krutik_api.db")

# Comma-separated list of approved upstream hostnames.
# Example: api.example.com,api.myprovider.com
ALLOWED_UPSTREAM_HOSTS = {
    host.strip().lower()
    for host in os.getenv("UPSTREAM_HOST_ALLOWLIST", "").split(",")
    if host.strip()
}

if not ADMIN_PASSWORD:
    raise RuntimeError("Set ADMIN_PASSWORD in environment variables.")

if len(SESSION_SECRET) < 32:
    raise RuntimeError("Set SESSION_SECRET to a random secret of at least 32 characters.")

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine_options = {}

if DATABASE_URL.startswith("sqlite"):
    engine_options["connect_args"] = {"check_same_thread": False}
else:
    engine_options["pool_pre_ping"] = True

engine = create_engine(DATABASE_URL, **engine_options)
SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    expire_on_commit=False
)

Base = declarative_base()

app = FastAPI(title=APP_NAME)

app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    same_site="lax",
    https_only=True,
    max_age=3600,
)


# =========================================================
# DATABASE MODELS
# =========================================================

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False)
    api_key_hash = Column(String(64), unique=True, nullable=False)
    api_key_prefix = Column(String(16), nullable=False)

    active = Column(Boolean, default=True, nullable=False)
    credits = Column(Integer, default=100, nullable=False)

    daily_limit = Column(Integer, default=100, nullable=False)
    total_limit = Column(Integer, default=1000, nullable=False)

    # NULL means no expiry.
    expires_at = Column(DateTime(timezone=True), nullable=True)

    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )


class ApiConfig(Base):
    __tablename__ = "api_configs"

    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    slug = Column(String(60), unique=True, nullable=False)

    upstream_url = Column(Text, nullable=False)
    upstream_key = Column(Text, nullable=True)
    upstream_key_param = Column(String(80), default="key", nullable=False)

    enabled = Column(Boolean, default=True, nullable=False)

    # Replace matching text in text or JSON responses.
    replace_from = Column(Text, nullable=True)
    replace_to = Column(Text, nullable=True)

    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )


class Assignment(Base):
    __tablename__ = "assignments"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    api_id = Column(Integer, ForeignKey("api_configs.id"), nullable=False)


class Usage(Base):
    __tablename__ = "usage"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, nullable=False)
    api_id = Column(Integer, nullable=False)

    status_code = Column(Integer, nullable=False)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )


Base.metadata.create_all(bind=engine)


# =========================================================
# HELPERS
# =========================================================

def now_utc():
    return datetime.now(timezone.utc)


def key_hash(api_key):
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def create_api_key():
    # Show the plaintext key once when the admin creates it.
    return "kcd_" + secrets.token_urlsafe(32)


def api_key_matches(user, supplied_key):
    if not supplied_key:
        return False

    candidate = key_hash(supplied_key)

    return hmac.compare_digest(user.api_key_hash, candidate)


def admin_logged_in(request):
    return request.session.get("admin_authenticated") is True


def admin_guard(request):
    if not admin_logged_in(request):
        return RedirectResponse("/admin/login", status_code=303)
    return None


def html_page(title, body):
    return HTMLResponse(f"""
    <!doctype html>
    <html lang="en">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width,initial-scale=1">
      <title>{escape(title)}</title>
      <style>
        :root {{
          color-scheme: dark;
          --bg:#080c16;
          --panel:#111827;
          --line:#263348;
          --text:#e5e7eb;
          --muted:#9ca3af;
          --accent:#22d3ee;
        }}
        * {{ box-sizing:border-box; }}
        body {{
          margin:0; padding:24px;
          font-family:system-ui,Arial,sans-serif;
          background:var(--bg); color:var(--text);
        }}
        main {{ max-width:1050px; margin:auto; }}
        h1,h2 {{ color:var(--accent); }}
        .card {{
          background:var(--panel); border:1px solid var(--line);
          border-radius:12px; padding:18px; margin:16px 0;
          overflow-wrap:anywhere;
        }}
        input,button {{
          width:100%; padding:11px; margin:6px 0;
          border-radius:7px; border:1px solid var(--line);
          background:#0b1220; color:var(--text);
        }}
        button {{
          background:#164e63; cursor:pointer;
          border-color:#0891b2; font-weight:600;
        }}
        a {{ color:var(--accent); }}
        table {{ width:100%; border-collapse:collapse; }}
        th,td {{
          padding:10px; border-bottom:1px solid var(--line);
          text-align:left; vertical-align:top;
        }}
        .tablewrap {{ overflow-x:auto; }}
        .muted {{ color:var(--muted); }}
        .grid {{
          display:grid; grid-template-columns:repeat(auto-fit,minmax(240px,1fr));
          gap:12px;
        }}
        .inline {{ display:inline-block; width:auto; }}
        .inline button {{ width:auto; }}
        code {{ overflow-wrap:anywhere; }}
      </style>
    </head>
    <body><main>
      <h1>{escape(APP_NAME)}</h1>
      {body}
    </main></body></html>
    """)


def validate_upstream(url):
    try:
        parsed = urlparse(url)
    except Exception:
        return False

    if parsed.scheme != "https":
        return False

    if not parsed.hostname:
        return False

    if parsed.username or parsed.password:
        return False

    if parsed.port not in (None, 443):
        return False

    hostname = parsed.hostname.lower().rstrip(".")

    if not ALLOWED_UPSTREAM_HOSTS:
        return False

    # Exact hostname matching avoids suffix-confusion attacks.
    return hostname in ALLOWED_UPSTREAM_HOSTS


def get_user_by_key(db, supplied_key):
    if not supplied_key or len(supplied_key) > 200:
        return None

    user = db.query(User).filter(
        User.api_key_hash == key_hash(supplied_key)
    ).first()

    if not user or not api_key_matches(user, supplied_key):
        return None

    if not user.active:
        return None

    if user.expires_at:
        expiry = user.expires_at

        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)

        if expiry <= now_utc():
            return None

    return user


def get_api_by_slug(db, slug):
    if not re.fullmatch(r"[a-z0-9_-]{1,60}", slug):
        return None

    return db.query(ApiConfig).filter(
        ApiConfig.slug == slug,
        ApiConfig.enabled.is_(True)
    ).first()


def user_has_api(db, user_id, api_id):
    return db.query(Assignment).filter(
        Assignment.user_id == user_id,
        Assignment.api_id == api_id
    ).first() is not None


def usage_counts(db, user):
    midnight = now_utc().replace(
        hour=0, minute=0, second=0, microsecond=0
    )

    daily = db.query(func.count(Usage.id)).filter(
        Usage.user_id == user.id,
        Usage.created_at >= midnight
    ).scalar() or 0

    total = db.query(func.count(Usage.id)).filter(
        Usage.user_id == user.id
    ).scalar() or 0

    return daily, total


def record_usage(db, user_id, api_id, status_code):
    row = Usage(
        user_id=user_id,
        api_id=api_id,
        status_code=status_code
    )
    db.add(row)
    db.commit()


# =========================================================
# PUBLIC WEBSITE
# =========================================================

@app.get("/", include_in_schema=False)
def homepage():
    return HTMLResponse(
        "<h1>404 Not Found</h1>",
        status_code=404
    )


@app.get("/health")
def health():
    return {"status": "ok"}


# =========================================================
# ADMIN LOGIN
# =========================================================

@app.get("/admin", include_in_schema=False)
def admin_home(request: Request):
    if not admin_logged_in(request):
        return RedirectResponse("/admin/login", status_code=303)

    return RedirectResponse("/admin/dashboard", status_code=303)


@app.get("/admin/login", response_class=HTMLResponse)
def login_page():
    return html_page("Admin Login", """
      <div class="card">
        <h2>Admin Login</h2>
        <form method="post" action="/admin/login">
          <input type="password" name="password"
                 placeholder="Admin password" required>
          <button type="submit">Login</button>
        </form>
      </div>
    """)


@app.post("/admin/login")
def login(request: Request, password: str = Form(...)):
    if not hmac.compare_digest(password, ADMIN_PASSWORD):
        return html_page("Login Failed", """
          <div class="card">
            <p>Invalid password.</p>
            <a href="/admin/login">Try again</a>
          </div>
        """)

    request.session.clear()
    request.session["admin_authenticated"] = True

    return RedirectResponse("/admin/dashboard", status_code=303)


@app.post("/admin/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/admin/login", status_code=303)


# =========================================================
# ADMIN DASHBOARD
# =========================================================

@app.get("/admin/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    guard = admin_guard(request)
    if guard:
        return guard

    with SessionLocal() as db:
        users = db.query(User).order_by(User.id.desc()).all()
        apis = db.query(ApiConfig).order_by(ApiConfig.id.desc()).all()

        total_requests = db.query(func.count(Usage.id)).scalar() or 0

        user_rows = ""

        for user in users:
            daily, total = usage_counts(db, user)

            user_rows += f"""
            <tr>
              <td>{user.id}</td>
              <td>{escape(user.username)}</td>
              <td><code>{escape(user.api_key_prefix)}...</code></td>
              <td>{user.credits}</td>
              <td>{daily}/{user.daily_limit}</td>
              <td>{total}/{user.total_limit}</td>
              <td>{"Active" if user.active else "Blocked"}</td>
              <td>
                <form method="post" action="/admin/users/{user.id}/toggle">
                  <button>Toggle status</button>
                </form>
                <form method="post" action="/admin/users/{user.id}/key">
                  <button>Reset key</button>
                </form>
              </td>
            </tr>
            """

        api_rows = ""

        for api in apis:
            assigned = db.query(func.count(Assignment.id)).filter(
                Assignment.api_id == api.id
            ).scalar() or 0

            api_rows += f"""
            <tr>
              <td>{api.id}</td>
              <td>{escape(api.name)}</td>
              <td><code>{escape(api.slug)}</code></td>
              <td>{"ON" if api.enabled else "OFF"}</td>
              <td>{assigned}</td>
              <td>
                <form method="post" action="/admin/apis/{api.id}/toggle">
                  <button>Toggle API</button>
                </form>
              </td>
            </tr>
            """

        body = f"""
        <div class="card">
          <form method="post" action="/admin/logout">
            <button>Logout</button>
          </form>
          <h2>Dashboard</h2>
          <div class="grid">
            <div class="card">Users: <strong>{len(users)}</strong></div>
            <div class="card">APIs: <strong>{len(apis)}</strong></div>
            <div class="card">Total requests: <strong>{total_requests}</strong></div>
          </div>
        </div>

        <div class="card">
          <h2>Create User</h2>
          <form method="post" action="/admin/users">
            <input name="username" placeholder="Username" required>
            <input name="credits" type="number" min="0"
                   value="100" placeholder="Credits" required>
            <input name="daily_limit" type="number" min="0"
                   value="100" placeholder="Daily limit; 0 = unlimited" required>
            <input name="total_limit" type="number" min="0"
                   value="1000" placeholder="Total limit; 0 = unlimited" required>
            <input name="validity_days" type="number" min="0"
                   value="30" placeholder="Validity days; 0 = no expiry" required>
            <button>Create user</button>
          </form>
          <p class="muted">
            The newly generated API key is shown only once.
          </p>
        </div>

        <div class="card">
          <h2>Users</h2>
          <div class="tablewrap"><table>
            <tr>
              <th>ID</th><th>User</th><th>Key prefix</th>
              <th>Credits</th><th>Daily</th><th>Total</th>
              <th>Status</th><th>Actions</th>
            </tr>
            {user_rows}
          </table></div>
        </div>

        <div class="card">
          <h2>Add API</h2>
          <form method="post" action="/admin/apis">
            <input name="name" placeholder="API name" required>
            <input name="slug" placeholder="API slug (e.g. weather)" required>
            <input name="upstream_url" type="url"
                   placeholder="HTTPS upstream URL" required>
            <input name="upstream_key"
                   placeholder="Upstream secret (optional)">
            <input name="upstream_key_param" value="key"
                   placeholder="Upstream credential parameter name">
            <input name="replace_from"
                   placeholder="Exact text to replace (optional)">
            <input name="replace_to"
                   placeholder="Replacement text (optional)">
            <button>Add API</button>
          </form>
          <p class="muted">
            Upstream hostname must be listed in UPSTREAM_HOST_ALLOWLIST.
            API keys should preferably be sent in headers by upstream providers.
          </p>
        </div>

        <div class="card">
          <h2>APIs</h2>
          <div class="tablewrap"><table>
            <tr><th>ID</th><th>Name</th><th>Slug</th>
                <th>Status</th><th>Assigned users</th><th>Action</th></tr>
            {api_rows}
          </table></div>
        </div>

        <div class="card">
          <h2>Assign API to User</h2>
          <form method="post" action="/admin/assign">
            <input name="user_id" type="number" min="1"
                   placeholder="User ID" required>
            <input name="api_id" type="number" min="1"
                   placeholder="API ID" required>
            <button>Assign access</button>
          </form>
        </div>

        <div class="card">
          <h2>API usage</h2>
          <p>Usage is counted by user and includes failed upstream requests.</p>
          <a href="/admin/usage">View usage log</a>
        </div>
        """

        return html_page("Dashboard", body)


# =========================================================
# USER MANAGEMENT
# =========================================================

@app.post("/admin/users")
def create_user(
    request: Request,
    username: str = Form(...),
    credits: int = Form(...),
    daily_limit: int = Form(...),
    total_limit: int = Form(...),
    validity_days: int = Form(...)
):
    guard = admin_guard(request)
    if guard:
        return guard

    username = username.strip()

    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", username):
        return HTMLResponse("Invalid username", status_code=400)

    if min(credits, daily_limit, total_limit, validity_days) < 0:
        return HTMLResponse("Limits cannot be negative", status_code=400)

    raw_key = create_api_key()
    expiry = (
        now_utc() + timedelta(days=validity_days)
        if validity_days > 0 else None
    )

    with SessionLocal() as db:
        existing = db.query(User).filter(
            User.username == username
        ).first()

        if existing:
            return HTMLResponse("Username already exists", status_code=409)

        user = User(
            username=username,
            api_key_hash=key_hash(raw_key),
            api_key_prefix=raw_key[:12],
            credits=credits,
            daily_limit=daily_limit,
            total_limit=total_limit,
            expires_at=expiry
        )

        db.add(user)
        db.commit()

    return html_page("User Created", f"""
      <div class="card">
        <h2>User created</h2>
        <p>Username: {escape(username)}</p>
        <p>Save this API key now. It will not be shown again:</p>
        <code>{escape(raw_key)}</code>
        <p><a href="/admin/dashboard">Return to dashboard</a></p>
      </div>
    """)


@app.post("/admin/users/{user_id}/toggle")
def toggle_user(request: Request, user_id: int):
    guard = admin_guard(request)
    if guard:
        return guard

    with SessionLocal() as db:
        user = db.get(User, user_id)

        if not user:
            return HTMLResponse("User not found", status_code=404)

        user.active = not user.active
        db.commit()

    return RedirectResponse("/admin/dashboard", status_code=303)


@app.post("/admin/users/{user_id}/key")
def reset_user_key(request: Request, user_id: int):
    guard = admin_guard(request)
    if guard:
        return guard

    raw_key = create_api_key()

    with SessionLocal() as db:
        user = db.get(User, user_id)

        if not user:
            return HTMLResponse("User not found", status_code=404)

        user.api_key_hash = key_hash(raw_key)
        user.api_key_prefix = raw_key[:12]
        db.commit()

        username = user.username

    return html_page("Key Reset", f"""
      <div class="card">
        <h2>API key reset</h2>
        <p>User: {escape(username)}</p>
        <p>Save the new key now. The old key has been revoked:</p>
        <code>{escape(raw_key)}</code>
        <p><a href="/admin/dashboard">Return to dashboard</a></p>
      </div>
    """)


# =========================================================
# API MANAGEMENT
# =========================================================

@app.post("/admin/apis")
def create_api(
    request: Request,
    name: str = Form(...),
    slug: str = Form(...),
    upstream_url: str = Form(...),
    upstream_key: str = Form(""),
    upstream_key_param: str = Form("key"),
    replace_from: str = Form(""),
    replace_to: str = Form("")
):
    guard = admin_guard(request)
    if guard:
        return guard

    name = name.strip()
    slug = slug.strip().lower()
    upstream_key_param = upstream_key_param.strip()

    if not re.fullmatch(r"[a-z0-9_-]{1,60}", slug):
        return HTMLResponse("Invalid API slug", status_code=400)

    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", upstream_key_param):
        return HTMLResponse("Invalid upstream key parameter", status_code=400)

    if not validate_upstream(upstream_url):
        return HTMLResponse(
            "Upstream HTTPS hostname is not in UPSTREAM_HOST_ALLOWLIST.",
            status_code=400
        )

    with SessionLocal() as db:
        if db.query(ApiConfig).filter(ApiConfig.slug == slug).first():
            return HTMLResponse("API slug already exists", status_code=409)

        api = ApiConfig(
            name=name,
            slug=slug,
            upstream_url=upstream_url,
            upstream_key=upstream_key or None,
            upstream_key_param=upstream_key_param,
            replace_from=replace_from or None,
            replace_to=replace_to or None
        )

        db.add(api)
        db.commit()

    return RedirectResponse("/admin/dashboard", status_code=303)


@app.post("/admin/apis/{api_id}/toggle")
def toggle_api(request: Request, api_id: int):
    guard = admin_guard(request)
    if guard:
        return guard

    with SessionLocal() as db:
        api = db.get(ApiConfig, api_id)

        if not api:
            return HTMLResponse("API not found", status_code=404)

        api.enabled = not api.enabled
        db.commit()

    return RedirectResponse("/admin/dashboard", status_code=303)


@app.post("/admin/assign")
def assign_api(
    request: Request,
    user_id: int = Form(...),
    api_id: int = Form(...)
):
    guard = admin_guard(request)
    if guard:
        return guard

    with SessionLocal() as db:
        user = db.get(User, user_id)
        api = db.get(ApiConfig, api_id)

        if not user or not api:
            return HTMLResponse("User or API not found", status_code=404)

        if not user_has_api(db, user_id, api_id):
            db.add(Assignment(user_id=user_id, api_id=api_id))
            db.commit()

    return RedirectResponse("/admin/dashboard", status_code=303)


# =========================================================
# USAGE LOG
# =========================================================

@app.get("/admin/usage", response_class=HTMLResponse)
def usage_page(request: Request):
    guard = admin_guard(request)
    if guard:
        return guard

    with SessionLocal() as db:
        rows = (
            db.query(Usage, User, ApiConfig)
            .outerjoin(User, Usage.user_id == User.id)
            .outerjoin(ApiConfig, Usage.api_id == ApiConfig.id)
            .order_by(Usage.id.desc())
            .limit(500)
            .all()
        )

        content = ""

        for usage, user, api in rows:
            content += f"""
            <tr>
              <td>{usage.id}</td>
              <td>{escape(user.username) if user else "Deleted user"}</td>
              <td>{escape(api.slug) if api else "Deleted API"}</td>
              <td>{usage.status_code}</td>
              <td>{escape(str(usage.created_at))}</td>
            </tr>
            """

    return html_page("Usage Log", f"""
      <div class="card">
        <h2>Latest 500 requests</h2>
        <div class="tablewrap"><table>
          <tr><th>ID</th><th>User</th><th>API</th><th>Status</th><th>Time</th></tr>
          {content}
        </table></div>
        <a href="/admin/dashboard">Back to dashboard</a>
      </div>
    """)


# =========================================================
# AUTHORIZED API PROXY
# =========================================================

@app.get("/api/{slug}")
async def api_proxy(slug: str, request: Request):
    supplied_key = request.query_params.get("key", "")

    with SessionLocal() as db:
        user = get_user_by_key(db, supplied_key)

        if not user:
            return JSONResponse(
                {"error": "Invalid, blocked, or expired API key"},
                status_code=401
            )

        api = get_api_by_slug(db, slug)

        if not api:
            return JSONResponse(
                {"error": "API not found or disabled"},
                status_code=404
            )

        if not user_has_api(db, user.id, api.id):
            return JSONResponse(
                {"error": "You do not have access to this API"},
                status_code=403
            )

        daily_count, total_count = usage_counts(db, user)

        if user.credits <= 0:
            return JSONResponse({"error": "No credits remaining"}, status_code=429)

        if user.daily_limit > 0 and daily_count >= user.daily_limit:
            return JSONResponse(
                {"error": "Daily request limit reached"},
                status_code=429
            )

        if user.total_limit > 0 and total_count >= user.total_limit:
            return JSONResponse(
                {"error": "Total request limit reached"},
                status_code=429
            )

        # Only forward caller-supplied parameters, excluding our own key.
        params = {
            name: value
            for name, value in request.query_params.multi_items()
            if name != "key"
        }

        if api.upstream_key:
            params[api.upstream_key_param] = api.upstream_key

        # Recheck the hostname before every outbound request.
        if not validate_upstream(api.upstream_url):
            return JSONResponse(
                {"error": "Upstream host is not approved"},
                status_code=502
            )

        # Consume a credit before the outbound request. This prevents
        # repeatedly calling an API without paying for failed responses.
        user.credits -= 1
        db.commit()

        user_id = user.id
        api_id = api.id
        replacement_from = api.replace_from
        replacement_to = api.replace_to

        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(15.0),
                follow_redirects=False,
                trust_env=False
            ) as client:
                upstream_response = await client.get(
                    api.upstream_url,
                    params=params,
                    headers={"Accept": "application/json, text/plain"},
                )

            # Do not forward upstream headers, cookies, or secrets.
            content_type = upstream_response.headers.get(
                "content-type", "application/json"
            )

            body = upstream_response.content

            # Keep responses bounded to avoid excessive memory use.
            if len(body) > 2_000_000:
                record_usage(db, user_id, api_id, 502)
                return JSONResponse(
                    {"error": "Upstream response exceeded the size limit"},
                    status_code=502
                )

            try:
                text_body = body.decode("utf-8")
            except UnicodeDecodeError:
                record_usage(db, user_id, api_id, 502)
                return JSONResponse(
                    {"error": "Unsupported upstream response encoding"},
                    status_code=502
                )

            if replacement_from:
                text_body = text_body.replace(
                    replacement_from,
                    replacement_to or ""
                )

            record_usage(
                db, user_id, api_id, upstream_response.status_code
            )

            return HTMLResponse(
                text_body,
                status_code=upstream_response.status_code,
                media_type=content_type.split(";")[0]
            )

        except httpx.TimeoutException:
            record_usage(db, user_id, api_id, 504)
            return JSONResponse(
                {"error": "Upstream API timed out"},
                status_code=504
            )

        except httpx.RequestError:
            record_usage(db, user_id, api_id, 502)
            return JSONResponse(
                {"error": "Unable to reach upstream API"},
                status_code=502
            )


# =========================================================
# STARTUP
# =========================================================

@app.on_event("startup")
async def startup_message():
    print(f"{APP_NAME} started")
