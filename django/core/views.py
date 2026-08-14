import json

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from .models import CustomHeader, Project, ProjectNote, ScopeEntry
from .notes import render_note_text
from .project_transfer import export_project, import_project


@login_required
def project_list(request):
    if request.method == "POST":
        name = request.POST.get("name", "").strip()
        if name:
            project, created = Project.objects.get_or_create(name=name)
            if created:
                messages.success(request, f"Created project '{name}'.")
            else:
                messages.info(request, f"Project '{name}' already exists.")
        return redirect("core:project_list")

    projects = Project.objects.all()
    return render(request, "core/project_list.html", {"projects": projects})


@login_required
def project_create(request):
    if request.method == "POST":
        name = request.POST.get("name", "").strip()
        if not name:
            messages.error(request, "Project name is required.")
            return redirect("core:project_create")

        project, created = Project.objects.get_or_create(
            name=name,
            defaults={
                "description": request.POST.get("description", "").strip(),
                "rules": request.POST.get("rules", "").strip(),
            },
        )
        if not created:
            messages.info(request, f"Project '{name}' already exists.")
            return redirect("core:project_list")

        for pattern in request.POST.get("in_scope", "").splitlines():
            pattern = pattern.strip()
            if pattern:
                ScopeEntry.objects.create(project=project, pattern=pattern, exclude=False)
        for pattern in request.POST.get("out_of_scope", "").splitlines():
            pattern = pattern.strip()
            if pattern:
                ScopeEntry.objects.create(project=project, pattern=pattern, exclude=True)

        for i in range(1, 4):
            header_name = request.POST.get(f"header_name_{i}", "").strip()
            if not header_name:
                continue
            CustomHeader.objects.create(
                project=project,
                name=header_name,
                value=request.POST.get(f"header_value_{i}", ""),
                append_to_existing=request.POST.get(f"header_append_{i}") == "on",
                apply_to_proxy_traffic=request.POST.get(f"header_proxy_{i}") == "on",
                apply_to_tool_traffic=request.POST.get(f"header_tool_{i}") == "on",
            )

        messages.success(request, f"Created project '{name}'.")
        return redirect("core:project_list")

    return render(request, "core/project_create.html")


@login_required
def project_edit(request, pk):
    project = get_object_or_404(Project, pk=pk)

    if request.method == "POST":
        name = request.POST.get("name", "").strip()
        if not name:
            messages.error(request, "Project name is required.")
            return redirect("core:project_edit", pk=project.pk)
        if Project.objects.exclude(pk=project.pk).filter(name=name).exists():
            messages.error(request, f"A project named '{name}' already exists.")
            return redirect("core:project_edit", pk=project.pk)

        project.name = name
        project.description = request.POST.get("description", "").strip()
        project.rules = request.POST.get("rules", "").strip()
        project.save(update_fields=["name", "description", "rules"])
        messages.success(request, f"Saved '{project.name}'.")
        return redirect("core:project_list")

    return render(request, "core/project_edit.html", {"project": project})


@login_required
def project_activate(request, pk):
    project = get_object_or_404(Project, pk=pk)
    project.is_active = True
    project.save()
    messages.success(request, f"'{project.name}' is now the active project.")
    return redirect("core:project_list")


@login_required
@require_POST
def project_delete(request, pk):
    project = get_object_or_404(Project, pk=pk)
    name = project.name
    project.delete()
    messages.success(request, f"Deleted project '{name}' and all its data.")
    return redirect("core:project_list")


@login_required
def project_export(request, pk):
    project = get_object_or_404(Project, pk=pk)
    data = export_project(project)
    response = HttpResponse(json.dumps(data, indent=2), content_type="application/json")
    response["Content-Disposition"] = f'attachment; filename="{project.name}-export.json"'
    return response


@login_required
@require_POST
def project_import(request):
    uploaded = request.FILES.get("import_file")
    if not uploaded:
        messages.error(request, "Choose a file to import.")
        return redirect("core:project_list")

    try:
        data = json.loads(uploaded.read().decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        messages.error(request, "That file isn't valid JSON.")
        return redirect("core:project_list")

    try:
        project = import_project(data)
    except (ValueError, KeyError) as exc:
        messages.error(request, f"Import failed: {exc}")
        return redirect("core:project_list")

    messages.success(request, f"Imported as project '{project.name}'.")
    return redirect("core:project_list")


@login_required
def scope_list(request):
    project = Project.get_active()

    if request.method == "POST":
        pattern = request.POST.get("pattern", "").strip()
        note = request.POST.get("note", "").strip()
        exclude = request.POST.get("exclude") == "on"
        if pattern:
            ScopeEntry.objects.create(project=project, pattern=pattern, note=note, exclude=exclude)
            messages.success(request, f"Added {'exclusion' if exclude else 'scope entry'} '{pattern}'.")
        return redirect("core:scope_list")

    return render(request, "core/scope_list.html", {"project": project})


@login_required
def scope_delete(request, pk):
    entry = get_object_or_404(ScopeEntry, pk=pk, project=Project.get_active())
    entry.delete()
    messages.success(request, "Removed scope entry.")
    return redirect("core:scope_list")


@login_required
def set_capture_mode(request):
    project = Project.get_active()
    mode = request.POST.get("capture_mode", "")
    if mode in dict(Project.CAPTURE_MODE_CHOICES):
        project.capture_mode = mode
        project.save()
        messages.success(request, f"Capture mode set to '{project.get_capture_mode_display()}'.")
    return redirect("core:scope_list")


@login_required
def header_list(request):
    project = Project.get_active()

    if request.method == "POST":
        name = request.POST.get("name", "").strip()
        value = request.POST.get("value", "")
        append_to_existing = request.POST.get("append_to_existing") == "on"
        apply_to_proxy_traffic = request.POST.get("apply_to_proxy_traffic") == "on"
        apply_to_tool_traffic = request.POST.get("apply_to_tool_traffic") == "on"
        if name:
            CustomHeader.objects.create(
                project=project,
                name=name,
                value=value,
                append_to_existing=append_to_existing,
                apply_to_proxy_traffic=apply_to_proxy_traffic,
                apply_to_tool_traffic=apply_to_tool_traffic,
            )
            messages.success(request, f"Added header '{name}'.")
        return redirect("core:header_list")

    return render(request, "core/header_list.html", {"project": project})


@login_required
def header_delete(request, pk):
    header = get_object_or_404(CustomHeader, pk=pk, project=Project.get_active())
    header.delete()
    messages.success(request, "Removed header.")
    return redirect("core:header_list")


def _is_ajax(request):
    return request.headers.get("X-Requested-With") == "XMLHttpRequest"


@login_required
def notes_list(request):
    project = Project.get_active()

    if request.method == "POST":
        text = request.POST.get("text", "").strip()
        if not text:
            if _is_ajax(request):
                return JsonResponse({"error": "empty"}, status=400)
            return redirect("core:notes_list")

        note = ProjectNote.objects.create(project=project, text=text)
        if _is_ajax(request):
            return JsonResponse({"id": note.pk})
        messages.success(request, "Note added.")
        return redirect(f"{reverse('core:notes_list')}?note={note.pk}")

    notes = list(project.notes.all())
    note_param = request.GET.get("note", "")
    is_new = note_param == "new"
    selected = None
    if not is_new and note_param:
        selected = next((n for n in notes if str(n.pk) == note_param), None)
    if not is_new and selected is None and notes:
        selected = notes[0]

    return render(
        request,
        "core/notes_list.html",
        {
            "project": project,
            "notes": notes,
            "selected": selected,
            "is_new": is_new,
            "selected_rendered": render_note_text(selected.text) if selected else "",
        },
    )


@login_required
@require_POST
def note_edit(request, pk):
    note = get_object_or_404(ProjectNote, pk=pk, project=Project.get_active())
    text = request.POST.get("text", "").strip()
    if not text:
        if _is_ajax(request):
            return JsonResponse({"error": "empty"}, status=400)
        return redirect("core:notes_list")

    note.text = text
    note.save(update_fields=["text", "updated_at"])
    if _is_ajax(request):
        return JsonResponse({
            "rendered": render_note_text(note.text),
            "updated_at": note.updated_at.strftime("%Y-%m-%d %H:%M"),
        })
    messages.success(request, "Note updated.")
    return redirect("core:notes_list")


@login_required
@require_POST
def note_delete(request, pk):
    note = get_object_or_404(ProjectNote, pk=pk, project=Project.get_active())
    note.delete()
    if _is_ajax(request):
        return JsonResponse({"deleted": True})
    messages.success(request, "Note removed.")
    return redirect("core:notes_list")


@csrf_exempt
def api_custom_headers(request):
    """Polled by the mitmproxy addon (shared-secret token auth, same as the
    ingest endpoint) so it can inject the active project's proxy-scoped
    custom headers into every request it forwards."""
    token = request.headers.get("X-Ingest-Token", "")
    if not settings.INGEST_TOKEN or token != settings.INGEST_TOKEN:
        return JsonResponse({"error": "unauthorized"}, status=401)

    project = Project.get_active()
    headers = list(
        project.custom_headers.filter(apply_to_proxy_traffic=True).values(
            "name", "value", "append_to_existing"
        )
    )
    return JsonResponse({"headers": headers})
