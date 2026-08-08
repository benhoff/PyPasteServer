from server_app.routes import router as auth_router
from server_app.sync_websocket import router as sync_router


def test_only_authentication_and_sync_client_routes_are_exposed() -> None:
    routes = {
        (route.path, type(route).__name__)
        for router in (auth_router, sync_router)
        for route in router.routes
    }

    assert ("/register", "APIRoute") in routes
    assert ("/login", "APIRoute") in routes
    assert ("/logout", "APIRoute") in routes
    assert ("/sync/v1", "APIWebSocketRoute") in routes
    assert not any(path in {"/clipboard", "/ws"} for path, _ in routes)
