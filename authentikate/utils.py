from authentikate.decode import adecode_token
from authentikate.settings import get_settings
from authentikate.base_models import AuthentikateSettings, JWTToken, Task
from authentikate import models
from authentikate.errors import (
    NoAuthorizationHeader,
    MalformedAuthorizationHeader,
    InvalidTaskAssignment,
)
from pydantic import ValidationError
import re
import logging
import json
import base64
from urllib.parse import parse_qsl, unquote_plus
from typing import Any

logger = logging.getLogger(__name__)  #


async def authenticate_token(token: str, settings: AuthentikateSettings) -> JWTToken:
    """
    Authenticate a token and return the auth context
    (containing user, app and scopes)

    """
    decoded: JWTToken

    if token in settings.static_tokens:
        decoded = settings.static_tokens[token]
    else:
        decoded = await adecode_token(token, settings)

    return decoded


jwt_re = re.compile(r"Bearer\s(?P<token>[^\s]*)")


def extract_plain_from_authorization(authorization: str) -> str:
    """
    Extract a plain token from an Authorization header

    Parameters
    ----------

    authorization : str
        The Authorization header

    Returns
    -------
    str
        The token
    """

    m = jwt_re.match(authorization)
    if m:
        token = m.group("token")
        return token

    raise MalformedAuthorizationHeader("Not a valid token")


async def authenticate_header(
    headers: dict[str, str],
    settings: AuthentikateSettings | None = None,
    task: Task | None = None,
) -> JWTToken:
    """
    Authenticate a request and return the auth context
    (containing user, app and scopes)

    """
    if not settings:
        settings = get_settings()

    authorization_header = None

    for i in settings.authorization_headers:
        authorization_header = headers.get(i, None)
        if authorization_header:
            break

    if not authorization_header:
        raise NoAuthorizationHeader("No Authorization header")

    token = await authenticate_token(
        extract_plain_from_authorization(authorization_header), settings
    )

    request_task = task or extract_task_from_rekuest_header(headers, settings)
    if request_task is not None:
        await validate_task_assignment(request_task, token)

    return token


async def validate_task_assignment(task: Task, token: JWTToken) -> None:
    """Validate that a task assignee belongs to the authenticated organization."""
    if task.user == token.sub:
        return

    if not token.active_org:
        raise InvalidTaskAssignment(
            "Cannot assign a task to another user without an active organization"
        )

    same_organization = await models.Membership.objects.filter(
        user__sub=task.user,
        user__iss=token.iss,
        organization__slug=token.active_org,
        blocked=False,
    ).aexists()

    if not same_organization:
        raise InvalidTaskAssignment(
            "Task assignee is not in the same organization as the authenticated user"
        )


def extract_task_from_rekuest_header(
    headers: dict[str, str], settings: AuthentikateSettings | None = None
) -> Task | None:
    """Extract and deserialize a Rekuest task header into a Task model.

    Returns None when no configured Rekuest header is present or when
    deserialization fails.

    Accepted formats:
    - base64url-encoded JSON representing the full task object
    - param=value pairs where args is base64url-encoded JSON
    """
    if not settings:
        settings = get_settings()

    task_header = None
    for header_name in settings.rekuest_header:
        task_header = headers.get(header_name, None)
        if task_header:
            break

    if not task_header:
        return None

    try:
        def decode_base64url_json(value: str) -> Any:
            padded = value + "=" * (-len(value) % 4)
            decoded = base64.urlsafe_b64decode(padded)
            return json.loads(decoded.decode("utf-8"))

        # param=value style headers.
        payload: dict[str, str] = {}
        if "=" in task_header:
            # query-string like: key=a&key2=b
            if "&" in task_header:
                query_pairs = parse_qsl(task_header, keep_blank_values=True)
                payload = {key: value for key, value in query_pairs}
            else:
                # comma-separated like: key=a,key2=b
                for segment in [part.strip() for part in task_header.split(",") if part.strip()]:
                    if "=" not in segment:
                        raise ValueError("Invalid param=value segment")
                    key, value = segment.split("=", maxsplit=1)
                    payload[key.strip()] = unquote_plus(value.strip())

            task_data: dict[str, Any] = {
                "id": payload.get("id"),
                "parent": payload.get("parent") or None,
                "user": payload.get("user"),
                "app": payload.get("app"),
                "action": payload.get("action"),
                "args": {},
            }

            # args is expected to be base64url-encoded JSON.
            raw_args = payload.get("args")
            if raw_args:
                task_data["args"] = decode_base64url_json(unquote_plus(raw_args))

            return Task.model_validate(task_data)

        # Full header as base64url-encoded JSON.
        decoded_task = decode_base64url_json(task_header)
        return Task.model_validate(decoded_task)
    except (ValidationError, ValueError, TypeError, json.JSONDecodeError):
        logger.debug("Failed to deserialize Rekuest task header", exc_info=True)
        return None


async def authenticate_header_or_none(
    headers: dict[str, str], settings: AuthentikateSettings | None = None
) -> JWTToken | None:
    """
    Authenticate a request header and return the auth context

    Parameters
    ----------
    headers : dict
        The headers to authenticate

    settings : AuthentikateSettings, optional
        The settings to use, by default None

    Returns
    -------
    Auth | None
        The auth context or None if the token is invalid


    """
    try:
        return await authenticate_header(headers, settings)
    except Exception:
        return None


async def authenticate_token_or_none(
    token: str, settings: AuthentikateSettings | None = None
) -> JWTToken | None:
    """
    Authenticate a token and return the auth context

    Tries to authenticate the token, if it fails it will return None


    Parameters
    ----------
    token : str
        The token to authenticate

    settings : AuthentikateSettings, optional
        The settings to use, by default None

    Returns
    -------
    Auth | None
        The auth context or None if the token is invalid


    """

    if not settings:
        settings = get_settings()

    try:
        return await authenticate_token(token, settings)
    except Exception:
        logger.debug("Token authentication failed", exc_info=True)
        return None
