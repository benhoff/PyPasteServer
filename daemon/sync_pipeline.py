from typing import Callable, Optional

# central state broker for the latest clipboard string
class SyncState:
    def __init__(self):
        self.last: Optional[str] = None

    def update_if_changed(self, s: str, meta: Optional[dict[str, int | str]], on_change: Callable[[str, Optional[dict[str, int | str]]], None]):
        if not s:
            return False
        if self.last == s:
            return False
        self.last = s
        on_change(s, meta)
        return True
