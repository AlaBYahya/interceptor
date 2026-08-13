from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0003_project_description'),
    ]

    operations = [
        migrations.AddField(
            model_name='project',
            name='rules',
            field=models.TextField(blank=True, help_text='Testing rules/policy: hours, rate limits, disallowed actions, disclosure terms, etc.'),
        ),
        migrations.AddField(
            model_name='scopeentry',
            name='exclude',
            field=models.BooleanField(default=False, help_text='Explicitly out of scope, overriding any in-scope pattern above it also matches (e.g. a wildcard carve-out).'),
        ),
        migrations.AddField(
            model_name='customheader',
            name='append_to_existing',
            field=models.BooleanField(default=False, help_text="Append this value to the header if it's already set, instead of only adding it when missing."),
        ),
    ]
