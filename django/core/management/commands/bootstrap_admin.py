import os

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = (
        "Create a superuser from ADMIN_USERNAME/ADMIN_EMAIL/ADMIN_PASSWORD "
        "env vars, if no superuser exists yet. Safe to run repeatedly."
    )

    def handle(self, *args, **options):
        User = get_user_model()
        if User.objects.filter(is_superuser=True).exists():
            self.stdout.write("Superuser already exists, skipping.")
            return

        username = os.environ.get("ADMIN_USERNAME")
        password = os.environ.get("ADMIN_PASSWORD")
        email = os.environ.get("ADMIN_EMAIL", "")

        if not username or not password:
            self.stdout.write(self.style.WARNING(
                "ADMIN_USERNAME/ADMIN_PASSWORD not set — skipping admin "
                "bootstrap. Create one manually with 'manage.py createsuperuser'."
            ))
            return

        User.objects.create_superuser(username=username, email=email, password=password)
        self.stdout.write(self.style.SUCCESS(f"Created superuser '{username}'."))
