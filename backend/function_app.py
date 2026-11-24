"""Kontinenten Azure Functions Python v2 API.

Public: GET /api/articles and GET /api/articles/{id}
Private: /api/editor/me, /api/editor/articles, /api/editor/articles/{id}
Authentication: Microsoft Entra v2 access token; roles server-side via EDITOR_ROLES_JSON.
Data store: Azure Cosmos DB for NoSQL (all items partitioned under /tenant).
"""
import json
import os
from functools import wraps
from datetime import datetime, timezone
from uuid import uuid4

import azure.functions as func
import jwt
from jwt import PyJWKClient
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


def validated_identity(req):
    raw = req.headers.get("Authorization", "")
    if not raw.startswith("Bearer "):
        raise APIError(401, "Please sign in")
    tenant = os.environ["ENTRA_TENANT_ID"]
    audience = os.environ["ENTRA_API_AUDIENCE"]
    spa = os.environ["ENTRA_SPA_CLIENT_ID"]
    jwks = PyJWKClient(f"https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys", cache_jwk_set=True)
    token = raw[7:]
    try:
        key = jwks.get_signing_key_from_jwt(token)
        claims = jwt.decode(token, key.key, algorithms=["RS256"], audience=audience,
                            issuer=f"https://login.microsoftonline.com/{tenant}/v2.0",
                            options={"require": ["exp", "iat", "iss", "aud", "tid", "oid"]})
    except (jwt.PyJWTError, ValueError):
        raise APIError(401, "Session expired or invalid") from None
    if claims.get("tid") != tenant or claims.get("azp") != spa:
        raise APIError(403, "Unexpected application")
    if "access_as_user" not in claims.get("scp", "").split():
        raise APIError(403, "Missing editorial API scope")
    object_id = claims["oid"]
    try:
        allowlist = json.loads(os.environ["EDITOR_ROLES_JSON"])
    except (KeyError, ValueError):
        raise APIError(503, "Editorial permissions not configured") from None
    role = allowlist.get(object_id)
    if role not in {"writer", "editor", "admin"}:
        raise APIError(403, "You are not on the editorial team")
    return {"id": object_id, "role": role, "name": claims.get("name") or claims.get("preferred_username") or "Editor"}


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
