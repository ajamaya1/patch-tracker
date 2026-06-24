"""CLI tests: argument wiring and command output (engine stubbed with a fake Graph)."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "src"))

from intuneassigner import cli  # noqa: E402
from intuneassigner.assignments import AssignmentEngine  # noqa: E402
from intuneassigner.directory import Directory  # noqa: E402
from intuneassigner.graph import GraphClient  # noqa: E402
from intune_fake import FakeGraph, grp_target  # noqa: E402

A = "11111111-1111-1111-1111-111111111111"
C = "33333333-3333-3333-3333-333333333333"


@pytest.fixture
def stub_engine(monkeypatch):
    fg = FakeGraph()
    fg.add_group(A, "All Workstations")
    fg.add_group(C, "New Devices")
    fg.add_collection(
        "deviceManagement/configurationPolicies",
        [{"id": "cp1", "name": "Win Baseline", "assignments": [{"target": grp_target(A)}]}],
    )
    client = GraphClient(lambda: "tok", transport=fg)
    engine = AssignmentEngine(client, Directory(client))
    monkeypatch.setattr(cli, "build_engine", lambda args: engine)
    return fg


def run(argv):
    return cli.main(argv)


def test_areas_lists_registry(capsys):
    assert run(["areas"]) == 0
    out = capsys.readouterr().out
    assert "Apps:" in out and "mobileApps" in out


def test_list_table(stub_engine, capsys):
    assert run(["list", "--token", "x", "--area", "Configuration"]) == 0
    out = capsys.readouterr().out
    assert "Win Baseline" in out and "All Workstations" in out


def test_group_reverse_lookup(stub_engine, capsys):
    assert run(["group", "All Workstations", "--token", "x"]) == 0
    out = capsys.readouterr().out
    assert "Assigned to 1 resource" in out
    assert "Win Baseline" in out


def test_copy_dry_run(stub_engine, capsys):
    rc = run(["copy", "--from", "All Workstations", "--to", "New Devices",
              "--token", "x", "--dry-run"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "DRY-RUN" in out
    assert stub_engine.posts == []  # nothing written


def test_unknown_group_errors(stub_engine, capsys):
    rc = run(["group", "Nope", "--token", "x"])
    assert rc == 2
    assert "No group found" in capsys.readouterr().err
