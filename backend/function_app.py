"""Kontinenten Azure Functions Python v2 API.

Public: GET /api/articles and GET /api/articles/{id}
Private: /api/editor/me, /api/editor/articles, /api/editor/articles/{id}
Authentication: email/password (Argon2id), short-lived opaque bearer sessions; roles stored server-side in Cosmos DB.
Data store: Azure Cosmos DB for NoSQL (all items partitioned under /tenant).
"""
import json
import os
import hashlib
import secrets
import re
from datetime import timedelta
from functools import wraps
from datetime import datetime, timezone
from uuid import uuid4

import azure.functions as func
from argon2 import PasswordHasher, exceptions as argon_errors
from azure.cosmos import CosmosClient, exceptions
from azure.identity import DefaultAzureCredential
from azure.core import MatchConditions

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)
TENANT = "kontinenten"
FIELDS = ("title", "category", "author_name", "summary", "body", "featured")
CATEGORIES = {"opinion", "report", "interview"}
STATUSES = {"draft", "review", "published"}
MAX_LENGTHS = {"title": 220, "author_name": 120, "summary": 600, "body": 80000}


def now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def reply(payload, status=200, headers=None):
    h = {"Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store"}
    h.update(headers or {})
    return func.HttpResponse(json.dumps(payload, ensure_ascii=False), status_code=status, headers=h)


class APIError(Exception):
    def __init__(self, status, message):
        self.status, self.message = status, message


def guarded(handler):
    @wraps(handler)
    def route(req: func.HttpRequest):
        try:
            return handler(req)
        except APIError as exc:
            return reply({"error": exc.message}, exc.status)
        except exceptions.CosmosResourceNotFoundError:
            return reply({"error": "Article not found"}, 404)
        except exceptions.CosmosHttpResponseError:
            return reply({"error": "Database request failed"}, 503)
        except Exception:
            import logging
            logging.exception("Unhandled API error")
            return reply({"error": "Internal server error"}, 500)
    return route


def db():
    endpoint = os.environ["COSMOS_ENDPOINT"]
    client = CosmosClient(endpoint, credential=DefaultAzureCredential())
    return client.get_database_client(os.getenv("COSMOS_DATABASE", "kontinenten")).get_container_client(
        os.getenv("COSMOS_CONTAINER", "articles"))


# Separate users container, partition key /tenant. No plaintext passwords.
# Session tokens exist only in the user's browser and are stored hashed in Cosmos DB.
PH = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)
SESSION_HOURS = 8
LOGIN_LIMIT = 5
LOCK_MINUTES = 15
EMAIL_RE = re.compile(r"^[^\s@]{1,64}@[^\s@]{1,190}$")


def users_db():
    endpoint = os.environ["COSMOS_ENDPOINT"]
    client = CosmosClient(endpoint, credential=DefaultAzureCredential())
    return client.get_database_client(os.getenv("COSMOS_DATABASE", "kontinenten")).get_container_client(
        os.getenv("COSMOS_USERS_CONTAINER", "users"))


def user_id(email):
    return "user:" + hashlib.sha256(email.lower().encode("utf-8")).hexdigest()


def session_id(token):
    return "session:" + hashlib.sha256(token.encode("ascii")).hexdigest()


def lookup_user(container, email):
    try:
        return container.read_item(item=user_id(email), partition_key=TENANT)
    except exceptions.CosmosResourceNotFoundError:
        return None


def input_json(req, size=10000):
    if len(req.get_body()) > size:
        raise APIError(413, "Request too large")
    try:
        data = req.get_json()
    except ValueError:
        raise APIError(400, "Invalid JSON") from None
    if not isinstance(data, dict):
        raise APIError(400, "Invalid JSON object")
    return data


def clean_email(value):
    email = value.strip().lower() if isinstance(value, str) else ""
    if len(email) > 254 or not EMAIL_RE.fullmatch(email):
        raise APIError(400, "Valid email address required")
    return email


def safe_user(user):
    return {"id": user["id"], "name": user["name"], "email": user["email"], "role": user["role"],
            "must_change_password": user.get("must_change_password", False)}


def validated_identity(req):
    raw = req.headers.get("Authorization", "")
    if not raw.startswith("Bearer ") or len(raw) > 120:
        raise APIError(401, "Please sign in")
    token = raw[7:]
    if not re.fullmatch(r"[A-Za-z0-9_-]{40,100}", token):
        raise APIError(401, "Invalid session")
    container = users_db()
    try:
        session = container.read_item(session_id(token), partition_key=TENANT)
    except exceptions.CosmosResourceNotFoundError:
        raise APIError(401, "Session expired or invalid") from None
    if session.get("type") != "session" or session.get("expires_at", "") < now():
        raise APIError(401, "Session expired or invalid")
    try:
        user = container.read_item(session["user_id"], partition_key=TENANT)
    except exceptions.CosmosResourceNotFoundError:
        raise APIError(401, "Account no longer active") from None
    if (user.get("type") != "user" or not user.get("enabled", False) or
            session.get("security_version") != user.get("security_version", 1)):
        raise APIError(401, "Account disabled or session revoked")
    # Password change is permitted even when a temporary password must be replaced.
    if user.get("must_change_password") and not req.url.endswith("/editor/change-password") and not req.url.endswith("/editor/logout") and not req.url.endswith("/editor/me"):
        raise APIError(403, "Change your temporary password before continuing")
    return safe_user(user)


def throttle_doc_id(email):
    return "throttle:" + hashlib.sha256(email.encode("utf-8")).hexdigest()


def attempt_state(container, email):
    try:
        return container.read_item(throttle_doc_id(email), partition_key=TENANT)
    except exceptions.CosmosResourceNotFoundError:
        return {"id": throttle_doc_id(email), "tenant": TENANT, "type": "throttle", "failures": 0, "lock_until": ""}


def failed_login(container, email, record):
    stamp = datetime.now(timezone.utc)
    record["failures"] = int(record.get("failures", 0)) + 1
    if record["failures"] >= LOGIN_LIMIT:
        record["lock_until"] = (stamp + timedelta(minutes=LOCK_MINUTES)).isoformat().replace("+00:00", "Z")
    # Account-level throttle shared across instances; protect public endpoint with
    # Azure Front Door/WAF or API Management rate limiting before wide deployment.
    container.upsert_item(record)


@app.route(route="editor/login", methods=["POST"])
@guarded
def editor_login(req):
    data = input_json(req)
    email = clean_email(data.get("email"))
    password = data.get("password")
    if not isinstance(password, str) or len(password) > 256:
        raise APIError(400, "Invalid login details")
    container = users_db()
    throttle = attempt_state(container, email)
    if throttle.get("lock_until", "") > now():
        raise APIError(429, "Too many login attempts. Try again in 15 minutes")
    if throttle.get("lock_until") and throttle["lock_until"] <= now():
        throttle["failures"] = 0
        throttle["lock_until"] = ""
    user = lookup_user(container, email)
    valid = False
    if user and user.get("enabled", False) and isinstance(user.get("password_hash"), str):
        try:
            valid = PH.verify(user["password_hash"], password)
        except (argon_errors.VerifyMismatchError, argon_errors.VerificationError, argon_errors.InvalidHashError):
            valid = False
    if not valid:
        failed_login(container, email, throttle)
        raise APIError(401, "Incorrect email or password")
    # Remove throttle on success.
    try:
        container.delete_item(item=throttle["id"], partition_key=TENANT)
    except exceptions.CosmosResourceNotFoundError:
        pass
    token = secrets.token_urlsafe(48)
    expiry = (datetime.now(timezone.utc) + timedelta(hours=SESSION_HOURS)).isoformat().replace("+00:00", "Z")
    container.create_item({"id": session_id(token), "tenant": TENANT, "type": "session",
                           "user_id": user["id"], "expires_at": expiry,
                           "security_version": user.get("security_version", 1)})
    return reply({"token": token, "expires_at": expiry, "user": safe_user(user)}, headers={"Cache-Control": "no-store"})


@app.route(route="editor/logout", methods=["POST"])
@guarded
def editor_logout(req):
    user = validated_identity(req)
    token = req.headers["Authorization"][7:]
    try:
        users_db().delete_item(item=session_id(token), partition_key=TENANT)
    except exceptions.CosmosResourceNotFoundError:
        pass
    return reply({"ok": True})


@app.route(route="editor/change-password", methods=["POST"])
@guarded
def editor_change_password(req):
    user = validated_identity(req)
    data = input_json(req)
    old = data.get("old_password")
    new = data.get("new_password")
    if not isinstance(old, str) or not isinstance(new, str) or not (12 <= len(new) <= 128):
        raise APIError(400, "New password must contain 12–128 characters")
    container = users_db()
    account = container.read_item(user["id"], partition_key=TENANT)
    try:
        PH.verify(account["password_hash"], old)
    except (argon_errors.VerifyMismatchError, argon_errors.VerificationError, argon_errors.InvalidHashError):
        raise APIError(401, "Current password is incorrect") from None
    account["password_hash"] = PH.hash(new)
    account["must_change_password"] = False
    account["security_version"] = account.get("security_version", 1) + 1
    container.replace_item(item=account["id"], body=account,
                           etag=account["_etag"], match_condition=MatchConditions.IfNotModified)
    return reply({"ok": True, "message": "Password changed. Please sign in again"})


@app.route(route="editor/users", methods=["POST"])
@guarded
def editor_create_user(req):
    acting = validated_identity(req)
    if acting["role"] != "admin":
        raise APIError(403, "Only administrators can add accounts")
    data = input_json(req)
    email = clean_email(data.get("email"))
    name = str(data.get("name", "")).strip()
    password = data.get("password")
    role = data.get("role")
    if not 1 <= len(name) <= 120 or role not in ("writer", "editor", "admin"):
        raise APIError(400, "Invalid name or role")
    if not isinstance(password, str) or not 12 <= len(password) <= 128:
        raise APIError(400, "Password must contain 12–128 characters")
    record = {"id": user_id(email), "tenant": TENANT, "type": "user", "email": email,
              "name": name, "role": role, "enabled": True, "security_version": 1,
              "must_change_password": True, "password_hash": PH.hash(password), "created_at": now()}
    try:
        users_db().create_item(record)
    except exceptions.CosmosResourceExistsError:
        raise APIError(409, "Account already exists") from None
    return reply({"user": safe_user(record)}, 201)


@app.route(route="editor/users/{account_id}/reset-password", methods=["POST"])
@guarded
def editor_reset_password(req):
    acting = validated_identity(req)
    if acting["role"] != "admin":
        raise APIError(403, "Only administrators can reset passwords")
    data = input_json(req)
    password = data.get("password")
    if not isinstance(password, str) or not 12 <= len(password) <= 128:
        raise APIError(400, "Password must contain 12–128 characters")
    account_id = req.route_params["account_id"]
    if not re.fullmatch(r"user:[0-9a-f]{64}", account_id):
        raise APIError(404, "Account not found")
    container = users_db()
    account = container.read_item(account_id, partition_key=TENANT)
    if account.get("type") != "user":
        raise APIError(404, "Account not found")
    account["password_hash"] = PH.hash(password)
    account["must_change_password"] = True
    account["security_version"] = account.get("security_version", 1) + 1
    container.replace_item(item=account_id, body=account,
                           etag=account["_etag"], match_condition=MatchConditions.IfNotModified)
    return reply({"ok": True})


def is_manager(user):
    return user["role"] in {"editor", "admin"}


def read_payload(req):
    if len(req.get_body()) > 110000:
        raise APIError(413, "Article too large")
    try:
        value = req.get_json()
    except ValueError:
        raise APIError(400, "Invalid JSON") from None
    if not isinstance(value, dict):
        raise APIError(400, "Expected an article object")
    record = {}
    for name in ("title", "author_name", "summary", "body"):
        val = value.get(name)
        if not isinstance(val, str) or not val.strip() or len(val) > MAX_LENGTHS[name]:
            raise APIError(400, f"Invalid {name} (required, max {MAX_LENGTHS[name]} characters)")
        record[name] = val.strip()
    if value.get("category") not in CATEGORIES:
        raise APIError(400, "Invalid category")
    record["category"] = value["category"]
    if not isinstance(value.get("featured", False), bool):
        raise APIError(400, "Featured must be true or false")
    record["featured"] = value.get("featured", False)
    return record


def get_item(container, article_id):
    if not article_id or len(article_id) > 64:
        raise APIError(404, "Article not found")
    return container.read_item(item=article_id, partition_key=TENANT)


def visible_to(user, item):
    return is_manager(user) or item.get("owner_id") == user["id"]


def public_item(item):
    return {k: item.get(k) for k in (
        "id", "title", "author_name", "summary", "body", "category", "featured", "published_at")}


def list_items(container, published_only=False):
    query = "SELECT * FROM c WHERE c.tenant=@t"
    if published_only:
        query += " AND c.status='published'"
    return list(container.query_items(
        query=query, parameters=[{"name": "@t", "value": TENANT}], partition_key=TENANT))


@app.route(route="articles", methods=["GET"])
@guarded
def published_list(req):
    items = list_items(db(), True)
    items.sort(key=lambda x: x.get("published_at") or "", reverse=True)
    return reply({"articles": [public_item(x) for x in items[:200]]}, headers={"Cache-Control": "public, max-age=60"})


@app.route(route="articles/{article_id}", methods=["GET"])
@guarded
def published_one(req):
    item = get_item(db(), req.route_params["article_id"])
    if item.get("status") != "published":
        raise APIError(404, "Article not found")
    return reply({"article": public_item(item)})


@app.route(route="editor/me", methods=["GET"])
@guarded
def editor_me(req):
    return reply({"user": validated_identity(req)})


@app.route(route="editor/articles", methods=["GET", "POST"])
@guarded
def editor_collection(req):
    user = validated_identity(req)
    container = db()
    if req.method == "GET":
        items = [x for x in list_items(container) if visible_to(user, x)]
        items.sort(key=lambda x: x.get("updated_at") or "", reverse=True)
        return reply({"articles": items[:500]})
    data = read_payload(req)
    stamp = now()
    item = {**data, "id": str(uuid4()), "tenant": TENANT, "owner_id": user["id"],
            "status": "draft", "created_at": stamp, "updated_at": stamp,
            "published_at": None, "version": 1}
    container.create_item(item)
    return reply({"article": item}, 201)


@app.route(route="editor/articles/{article_id}", methods=["GET", "PUT", "DELETE"])
@guarded
def editor_article(req):
    user = validated_identity(req)
    container = db()
    item = get_item(container, req.route_params["article_id"])
    if not visible_to(user, item):
        raise APIError(404, "Article not found")
    if req.method == "GET":
        return reply({"article": item})
    if req.method == "DELETE":
        if not is_manager(user):
            raise APIError(403, "Only editors can delete articles")
        container.delete_item(item=item, partition_key=TENANT,
                              etag=item["_etag"], match_condition=MatchConditions.IfNotModified)
        return reply({"ok": True})
    if item["status"] == "published" and not is_manager(user):
        raise APIError(403, "Only editors can edit published articles")
    try:
        request_json = req.get_json()
    except ValueError:
        raise APIError(400, "Invalid JSON") from None
    if request_json.get("expected_version") != item.get("version"):
        raise APIError(409, "This article has changed. Refresh and reopen it before editing")
    data = read_payload(req)
    item.update(data)
    item["updated_at"] = now()
    item["version"] = item.get("version", 1) + 1
    try:
        item = container.replace_item(item=item["id"], body=item,
                                      etag=item["_etag"], match_condition=MatchConditions.IfNotModified)
    except exceptions.CosmosHttpResponseError as exc:
        if exc.status_code == 412:
            raise APIError(409, "Someone edited this article. Refresh before saving") from None
        raise
    return reply({"article": item})


@app.route(route="editor/articles/{article_id}/status", methods=["POST"])
@guarded
def change_status(req):
    user = validated_identity(req)
    container = db()
    item = get_item(container, req.route_params["article_id"])
    if not visible_to(user, item):
        raise APIError(404, "Article not found")
    try:
        body = req.get_json()
    except ValueError:
        raise APIError(400, "Invalid JSON") from None
    target = body.get("status") if isinstance(body, dict) else None
    if not isinstance(body, dict) or body.get("expected_version") != item.get("version"):
        raise APIError(409, "Article changed; refresh before changing status")
    if target not in STATUSES:
        raise APIError(400, "Invalid status")
    if target == "published" or item["status"] == "published" or (target == "draft" and item["status"] == "review"):
        if not is_manager(user):
            raise APIError(403, "Only editors can publish, unpublish or return review drafts")
    if not is_manager(user) and target == "review" and item["status"] != "draft":
        raise APIError(403, "Only drafts can be submitted")
    if target == "published" and not all(item.get(k) for k in ("title", "summary", "body", "author_name")):
        raise APIError(400, "Article is incomplete")
    item["status"] = target
    item["updated_at"] = now()
    item["version"] = item.get("version", 1) + 1
    if target == "published":
        item["published_at"] = item.get("published_at") or now()
    else:
        item["published_at"] = None
    try:
        item = container.replace_item(item=item["id"], body=item,
                                      etag=item["_etag"], match_condition=MatchConditions.IfNotModified)
    except exceptions.CosmosHttpResponseError as exc:
        if exc.status_code == 412:
            raise APIError(409, "This article changed. Refresh before continuing") from None
        raise
    return reply({"article": item})
