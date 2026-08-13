import difflib

from django.contrib.auth.decorators import login_required
from django.shortcuts import render

from .codecs_ops import OPERATION_LABELS, OPERATIONS


@login_required
def decoder(request):
    operation = request.POST.get("operation", "base64_encode")
    input_text = ""
    output_text = ""

    if request.method == "POST":
        if request.POST.get("use_output") == "1":
            input_text = request.POST.get("prev_output", "")
        else:
            input_text = request.POST.get("input_text", "")
        fn = OPERATIONS.get(operation)
        output_text = fn(input_text) if fn else ""

    return render(
        request,
        "utils/decoder.html",
        {
            "input_text": input_text,
            "output_text": output_text,
            "operation": operation,
            "operations": OPERATION_LABELS,
        },
    )


@login_required
def comparer(request):
    if request.method == "POST":
        text_a = request.POST.get("text_a", "")
        text_b = request.POST.get("text_b", "")
        full_diff = list(
            difflib.unified_diff(text_a.splitlines(), text_b.splitlines(), fromfile="A", tofile="B", lineterm="")
        )
        # First two lines are always the "--- A"/"+++ B" file headers when
        # unified_diff produces any output — drop them so they don't get
        # colored as if they were removed/added content lines.
        diff_lines = full_diff[2:]
    else:
        text_a = request.GET.get("a", "")
        text_b = ""
        diff_lines = []

    return render(request, "utils/comparer.html", {"text_a": text_a, "text_b": text_b, "diff_lines": diff_lines})
