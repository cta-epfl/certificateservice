from typing import Any
import pytest
from flask import url_for


@pytest.mark.timeout(30)
def test_health(app: Any, client: Any):
    print(url_for('health'))
    r = client.get(url_for('health'))
    print(r.json, url_for('health'))
    assert r.status_code == 200
