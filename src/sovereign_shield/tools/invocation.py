"""Compatibility boundary for invoking pure functions wrapped as Strands tools."""

from __future__ import annotations

from typing import Any

try:
    from strands import tool
except ImportError:
    # The deployed deterministic runtime ships without the agent SDK. Tools are
    # then plain functions, which `invoke_tool` calls directly.
    def tool(func: Any) -> Any:
        return func


def invoke_tool(tool: Any, /, **kwargs: Any) -> Any:
    """Invoke a decorated tool's original callable without an agent runtime.

    Strands has exposed the wrapped callable under different attributes across
    releases. The application uses this one boundary for deterministic code
    paths, while agents still receive the decorated tool object.
    """

    for attribute in ("tool_func", "_tool_func", "__wrapped__"):
        callable_tool = getattr(tool, attribute, None)
        if callable(callable_tool):
            return callable_tool(**kwargs)

    if callable(tool):
        return tool(**kwargs)

    tool_name = getattr(tool, "tool_name", type(tool).__name__)
    raise TypeError(f"Tool '{tool_name}' does not expose an invokable callable")
