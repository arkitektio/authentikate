from authentikate.base_models import StaticToken
from authentikate.expand import expand_client_from_token
from authentikate.models import Client


def test_expand_client_allows_same_client_id_for_different_issuers(db):
    first_client = expand_client_from_token(
        StaticToken(sub="user-1", iss="issuer-one", client_id="shared-client")
    )
    second_client = expand_client_from_token(
        StaticToken(sub="user-2", iss="issuer-two", client_id="shared-client")
    )

    assert first_client.pk != second_client.pk
    assert Client.objects.filter(client_id="shared-client").count() == 2
