from .models import Project


def active_project(request):
    if not request.user.is_authenticated:
        return {}
    return {"active_project": Project.get_active()}
