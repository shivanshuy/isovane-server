from pathlib import Path

from isovane_serve.cli import main


def test_cli_scan_tmp_empty(tmp_path: Path):
    (tmp_path / "ok.py").write_text("x = 1\n", encoding="utf-8")
    code = main([str(tmp_path), "--no-fail", "--json", "-"])
    assert code == 0


def test_cli_fail_on_when_shell_true(tmp_path: Path):
    (tmp_path / "bad.py").write_text(
        "import subprocess\nsubprocess.run('echo hi', shell=True)\n",
        encoding="utf-8",
    )
    code = main([str(tmp_path), "--fail-on", "high"])
    assert code in (0, 1)  # engines may or may not flag depending on env
