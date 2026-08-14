from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0005_projectnote'),
    ]

    operations = [
        migrations.AlterField(
            model_name='project',
            name='capture_mode',
            field=models.CharField(
                choices=[('all', 'Save all proxied traffic'), ('in_scope', 'Save in-scope traffic only')],
                default='in_scope',
                max_length=10,
            ),
        ),
    ]
