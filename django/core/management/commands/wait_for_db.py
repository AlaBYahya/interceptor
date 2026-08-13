import time

from django.core.management.base import BaseCommand
from django.db import connections
from django.db.utils import OperationalError


class Command(BaseCommand):
    help = "Block until the database accepts connections."

    def handle(self, *args, **options):
        self.stdout.write("Waiting for database...")
        for _ in range(30):
            try:
                connections["default"].cursor()
                self.stdout.write(self.style.SUCCESS("Database is available."))
                return
            except OperationalError:
                time.sleep(1)
        self.stderr.write(self.style.ERROR("Database never became available."))
        raise SystemExit(1)
