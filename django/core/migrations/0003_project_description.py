from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0002_project_capture_mode'),
    ]

    operations = [
        migrations.AddField(
            model_name='project',
            name='description',
            field=models.TextField(blank=True),
        ),
    ]
