"""Optimistic-concurrency helpers (ETag / If-Match) for preference updates.

Protocol:
  * Every preferences response carries an ETag derived from the row's
    `version`.
  * Updates must send `If-Match` with the ETag they read. A missing If-Match
    is refused with 428; an ETag that no longer matches the row's version is
    refused with 412. The repository re-checks the version inside the UPDATE
    statement, so exactly one of several racing writers can succeed.
"""
ANY_VERSION = "*"


def etag_for(version: int) -> str:
    return f'"{version}"'


def if_match_allows(header_value: str, current_version: int) -> bool:
    """RFC 7232-style check of an If-Match header against the current version.

    Accepts a strong or weak entity tag ('"3"', 'W/"3"', '3') or a list of
    them; '*' matches any existing version. Anything unparseable fails closed
    so a malformed precondition can never mutate data.
    """
    for candidate in header_value.split(","):
        tag = candidate.strip()
        if tag == ANY_VERSION:
            return True
        if tag.startswith("W/"):
            tag = tag[2:].strip()
        if len(tag) >= 2 and tag.startswith('"') and tag.endswith('"'):
            tag = tag[1:-1]
        try:
            if int(tag) == current_version:
                return True
        except ValueError:
            continue
    return False
