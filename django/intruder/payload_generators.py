"""Server-side payload list generators for Intruder — mirrors Burp's
"Payload type" options (a curated subset: numbers, random numbers/strings,
null-byte/special-char presets). Each generator returns a list of strings
or None if the params were invalid.
"""

import random
import secrets
import string

MAX_GENERATED = 10000

# Textual representations only, deliberately no literal control character:
# Postgres text columns reject a raw null byte outright, so it could never
# be saved into payload_set anyway, and these escaped forms are what
# actually gets typed for this kind of test in practice.
NULL_AND_SPECIAL_PAYLOADS = [
    "%00",
    "\\x00",
    "\\u0000",
    " ",
    "../",
    "..\\",
    "....//",
    "%2e%2e%2f",
    "' OR '1'='1",
    '" OR "1"="1',
    "<script>alert(1)</script>",
    "{{7*7}}",
    "${7*7}",
    "|| id",
    "; id",
    "` id `",
    "NaN",
    "Infinity",
    "-1",
    "0",
    "999999999999999999",
]


def generate_number_range(start: int, end: int, step: int = 1):
    if step <= 0:
        step = 1
    if end < start or (end - start) // step > MAX_GENERATED:
        return None
    return [str(n) for n in range(start, end + 1, step)]


def generate_random_numbers(count: int, min_val: int = 0, max_val: int = 999999):
    if count <= 0 or count > MAX_GENERATED or max_val < min_val:
        return None
    return [str(random.randint(min_val, max_val)) for _ in range(count)]


def generate_random_strings(count: int, length: int = 8):
    if count <= 0 or count > MAX_GENERATED or length <= 0 or length > 256:
        return None
    alphabet = string.ascii_letters + string.digits
    return ["".join(secrets.choice(alphabet) for _ in range(length)) for _ in range(count)]


def generate_null_and_special():
    return list(NULL_AND_SPECIAL_PAYLOADS)


GENERATOR_LABELS = {
    "numbers": "Number range (start-end, step)",
    "random_numbers": "Random numbers (count, min, max)",
    "random_strings": "Random strings (count, length)",
    "null_special": "Null bytes / special chars (preset list)",
}


def generate_payloads(post_data):
    """post_data is a QueryDict (or dict) of form fields. Returns a list of
    payload strings, or None if the generator/params were invalid."""
    generator = post_data.get("generator", "")
    try:
        if generator == "numbers":
            start = int(post_data.get("start") or 0)
            end = int(post_data.get("end") or 0)
            step = int(post_data.get("step") or 1)
            return generate_number_range(start, end, step)
        if generator == "random_numbers":
            count = int(post_data.get("count") or 0)
            min_val = int(post_data.get("min") or 0)
            max_val = int(post_data.get("max") or 999999)
            return generate_random_numbers(count, min_val, max_val)
        if generator == "random_strings":
            count = int(post_data.get("count") or 0)
            length = int(post_data.get("length") or 8)
            return generate_random_strings(count, length)
        if generator == "null_special":
            return generate_null_and_special()
    except (TypeError, ValueError):
        return None
    return None
