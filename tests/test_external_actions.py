"""External plugin operations are covered with doubles, never live installs."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from binary_ninja_headless_mcp.backend import BinjaBackend
from binary_ninja_headless_mcp.fake_binja import FakeBinaryNinjaModule

from test_analysis_lifecycle import tool


@pytest.mark.parametrize("action", ["install", "uninstall", "enable", "disable"])
def test_repository_actions_use_test_double(action):
    plugin = SimpleNamespace(path="sample", name="Sample", installed=False, enabled=False)
    method = Mock(return_value=True)
    setattr(plugin, action, method)
    manager = SimpleNamespace(
        repositories=[SimpleNamespace(path="repo", plugins=[plugin])],
        check_for_updates=Mock(return_value=True),
    )
    module = FakeBinaryNinjaModule()
    module.RepositoryManager = lambda: manager
    backend = BinjaBackend(module)
    try:
        response = tool(
            backend,
            "plugin_repo.plugin_action",
            repository_path="repo",
            plugin_path="sample",
            action=action,
        )
        assert response["isError"] is False
        assert response["structuredContent"]["changed"] is True
        method.assert_called_once_with()
        dry = tool(backend, "plugin_repo.check_updates")
        assert dry["structuredContent"]["dry_run"] is True
        manager.check_for_updates.assert_not_called()
        real = tool(backend, "plugin_repo.check_updates", perform=True)
        assert real["structuredContent"]["checked"] is True
        manager.check_for_updates.assert_called_once_with()
    finally:
        backend.shutdown()


def test_plugin_execute_uses_double_and_honors_dry_run():
    command = SimpleNamespace(name="sample", execute=Mock(return_value=True))
    module = FakeBinaryNinjaModule()
    module.PluginCommand = [command]
    module.PluginCommandContext = lambda view: SimpleNamespace(view=view)
    backend = BinjaBackend(module)
    try:
        sid = backend.open_session("fixture", read_only=False)["session_id"]
        result = tool(backend, "plugin.execute", session_id=sid, name="sample")
        assert result["structuredContent"]["dry_run"] is True
        command.execute.assert_not_called()
        result = tool(backend, "plugin.execute", session_id=sid, name="sample", perform=True)
        assert result["structuredContent"]["executed"] is True
        command.execute.assert_called_once()
    finally:
        backend.shutdown()
