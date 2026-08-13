from django.apps import AppConfig


class ScannerConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "scanner"

    def ready(self):
        from traffic.signals import flow_ingested

        from .tasks import run_passive_checks

        def _on_flow_ingested(sender, flow_id, **kwargs):
            run_passive_checks.delay(flow_id)

        # weak=False: the receiver is a local closure with no other
        # reference anywhere, so a weak (the default) reference gets
        # garbage-collected almost immediately and the signal silently
        # stops firing it.
        flow_ingested.connect(_on_flow_ingested, weak=False)
