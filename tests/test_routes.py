from server_app.sync_websocket import router


def test_only_sync_client_route_is_exposed() -> None:
    routes = {(route.path, type(route).__name__) for route in router.routes}

    assert ("/sync/v1", "APIWebSocketRoute") in routes
    assert not any(
        path in {"/register", "/login", "/logout", "/clipboard", "/ws"}
        for path, _ in routes
    )
