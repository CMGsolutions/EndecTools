import subprocess

def test_endec_version():
    result = subprocess.run(["endec", "version"], capture_output=True, text=True)
    assert result.returncode == 0
    assert "EndecTools" in result.stdout

def test_endec_help():
    result = subprocess.run(["endec", "--help"], capture_output=True, text=True)
    assert result.returncode == 0
    assert "Usage" in result.stdout
