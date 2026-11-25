from fleet_tracker.http_api import create_app


def test_openapi_docs_are_enabled_and_grouped_for_mobile_clients() -> None:
    app = create_app(None, None)  # type: ignore[arg-type]

    schema = app.openapi()

    assert app.docs_url == "/api/docs"
    assert app.redoc_url == "/api/redoc"
    assert app.openapi_url == "/api/openapi.json"
    assert schema["info"]["title"] == "GPS Tracker API"
    assert "SessionCookie" in schema["components"]["securitySchemes"]
    assert schema["paths"]["/api/v1/orgs/{org_id}/vehicles/latest-state"]["get"]["tags"] == ["fleet"]
    assert schema["paths"]["/api/v1/orgs/{org_id}/vehicles/latest-state"]["get"]["security"] == [{"SessionCookie": []}]
    assert "security" not in schema["paths"]["/api/v1/auth/login"]["post"]
