# coding: utf-8
"""
Additional functions for pyproxmox
"""


def extract_code_and_json(response):
    """Extract status code and content from requests.Response instance.
    :param response: instance of requests.Response
    :returns : (code, content)
    """
    code = response.status_code
    try:
        content = response.json()
    except ValueError:
        content = response.text

    return code, content
