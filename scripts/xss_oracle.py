"""Small, dependency-free helpers for browser execution evidence."""


def execution_observed(http_status, title, marker, dialogs):
    """Return true only for an expected title marker or dialog on a 2xx page.

    A generic page-title change is not evidence that injected JavaScript ran:
    error pages such as an nginx 403 page also have titles.
    """
    if http_status is None or not 200 <= int(http_status) < 300:
        return False
    return (marker is not None and title == marker) or bool(dialogs)
