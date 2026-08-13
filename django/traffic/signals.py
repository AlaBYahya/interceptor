import django.dispatch

# Sent after a Flow is created via the ingest API. scanner/apps.py connects a
# receiver to this to enqueue passive-check analysis without traffic and
# scanner importing each other directly.
flow_ingested = django.dispatch.Signal()
