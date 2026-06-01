import base64

import pytest

from authentikate.base_models import Task
from authentikate.errors import InvalidTaskAssignment
from authentikate.models import Membership, Organization, User
from authentikate.utils import authenticate_header


def encode_args(args: bytes) -> str:
    return base64.urlsafe_b64encode(args).decode("utf-8").rstrip("=")


@pytest.mark.asyncio
async def test_authenticate_header_allows_task_assignee_in_same_org(
    db, valid_jwt, valid_settings
) -> None:
    organization, _ = await Organization.objects.aget_or_create(slug="kkk")
    assignee = await User.objects.acreate(username="assignee", sub="2", iss="XXXX")
    await Membership.objects.acreate(user=assignee, organization=organization, roles=[])

    task = Task.model_validate(
        {
            "id": "task-1",
            "parent": None,
            "args": {"x": 1},
            "user": "2",
            "app": "app-1",
            "action": "run",
        }
    )

    headers = {
        "Authorization": f"Bearer {valid_jwt}",
        "Rekuest-Task": (
            "id=task-1,parent=,"
            f"args={encode_args(b'{\"x\":1}')},user=2,app=app-1,action=run"
        ),
    }

    token = await authenticate_header(headers, valid_settings, task=task)
    assert token.sub == "1"


@pytest.mark.asyncio
async def test_authenticate_header_rejects_task_assignee_in_other_org(
    db, valid_jwt, valid_settings
) -> None:
    other_organization, _ = await Organization.objects.aget_or_create(slug="other-org")
    assignee = await User.objects.acreate(username="assignee-2", sub="3", iss="XXXX")
    await Membership.objects.acreate(
        user=assignee,
        organization=other_organization,
        roles=[],
    )

    headers = {
        "Authorization": f"Bearer {valid_jwt}",
        "Rekuest-Task": (
            "id=task-1,parent=,"
            f"args={encode_args(b'{\"x\":1}')},user=3,app=app-1,action=run"
        ),
    }

    with pytest.raises(InvalidTaskAssignment):
        await authenticate_header(headers, valid_settings)