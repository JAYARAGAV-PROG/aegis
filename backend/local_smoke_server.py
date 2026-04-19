from copy import deepcopy
from datetime import datetime
import os
import uuid

import uvicorn

import main


class FakeResult:
    def __init__(self, data=None, count=None):
        self.data = data if data is not None else []
        self.count = count


class FakeQuery:
    def __init__(self, db, table_name):
        self.db = db
        self.table_name = table_name
        self._op = "select"
        self._filters = []
        self._payload = None
        self._fields = "*"
        self._count = None
        self._order = None
        self._limit = None

    def select(self, fields="*", count=None):
        self._op = "select"
        self._fields = fields
        self._count = count
        return self

    def insert(self, payload):
        self._op = "insert"
        self._payload = payload
        return self

    def update(self, payload):
        self._op = "update"
        self._payload = payload
        return self

    def delete(self):
        self._op = "delete"
        return self

    def eq(self, field, value):
        self._filters.append((field, value))
        return self

    def order(self, field, desc=False):
        self._order = (field, desc)
        return self

    def limit(self, n):
        self._limit = n
        return self

    def _match(self, row):
        return all(row.get(field) == value for field, value in self._filters)

    def _with_join(self, rows):
        result = []
        for row in rows:
            item = deepcopy(row)
            if "endpoints(name)" in self._fields:
                endpoint = next(
                    (e for e in self.db.tables["endpoints"] if e["id"] == item.get("endpoint_id")),
                    None,
                )
                item["endpoints"] = {"name": endpoint["name"]} if endpoint else None
            result.append(item)
        return result

    def execute(self):
        rows = self.db.tables[self.table_name]

        if self._op == "insert":
            payloads = self._payload if isinstance(self._payload, list) else [self._payload]
            inserted = []
            for payload in payloads:
                item = deepcopy(payload)
                item.setdefault("id", str(uuid.uuid4()))
                item.setdefault("created_at", datetime.utcnow().isoformat())
                if self.table_name == "alerts":
                    item.setdefault("is_resolved", False)
                rows.append(item)
                inserted.append(deepcopy(item))
            return FakeResult(inserted)

        matched = [row for row in rows if self._match(row)]

        if self._op == "update":
            updated = []
            for row in matched:
                row.update(deepcopy(self._payload))
                updated.append(deepcopy(row))
            return FakeResult(updated)

        if self._op == "delete":
            deleted = [deepcopy(row) for row in matched]
            self.db.tables[self.table_name] = [row for row in rows if not self._match(row)]
            return FakeResult(deleted)

        result = self._with_join(matched)
        if self._order:
            field, desc = self._order
            result.sort(key=lambda row: row.get(field) or "", reverse=desc)
        if self._limit is not None:
            result = result[: self._limit]
        count = len(result) if self._count == "exact" else None
        return FakeResult(result, count=count)


class FakeSupabase:
    def __init__(self):
        self.tables = {
            "endpoints": [],
            "connections": [],
            "rules": [],
            "alerts": [],
        }

    def table(self, table_name):
        return FakeQuery(self, table_name)


async def fake_broadcast(_data):
    return None


async def fake_check_abuse(ip: str) -> int:
    if ip == "203.0.113.10":
        return 65
    return 0


async def fake_gemini_analyze(endpoint_name: str, process: str, conns: list) -> str:
    return (
        f"Local smoke mode: {process} on {endpoint_name} opened {len(conns)} "
        "connection(s); investigate if this was unexpected."
    )


main.supabase = FakeSupabase()
main.ws_manager.broadcast = fake_broadcast
main.check_abuse = fake_check_abuse
main.gemini_analyze = fake_gemini_analyze
main.ip_cache = {}


if __name__ == "__main__":
    port = int(os.getenv("AEGIS_SMOKE_PORT", "8000"))
    uvicorn.run(main.app, host="127.0.0.1", port=port)
