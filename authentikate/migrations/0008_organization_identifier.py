from django.db import migrations


class Migration(migrations.Migration):
    """An organization is named by its issuer and the issuer's id: ``slug`` becomes ``identifier``, ``"<iss>#<org>"``."""

    dependencies = [
        ("authentikate", "0007_user_profile"),
    ]

    operations = [
        migrations.RenameField(
            model_name="organization",
            old_name="slug",
            new_name="identifier",
        ),
    ]
