@echo off
echo Building ida_live_matching_diff wheels for distribution...
echo.

pip install maturin
maturin build --release --out dist/

echo.
echo Built wheels are in the dist/ folder.
echo You can install the generated .whl file into IDA Pro's Python environment via:
echo    "C:\Program Files\IDA Professional 9.1\python\3\python.exe" -m pip install dist\ida_matcher-0.1.0-cp39-abi3-win_amd64.whl
echo.
echo Then copy ida_live_matcher_plugin.py to IDA's plugins\ directory.
pause
