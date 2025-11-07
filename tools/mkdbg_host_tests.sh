#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
ATTACH_OUT="${TMP_DIR}/attach.out"
ATTACH_ERR="${TMP_DIR}/attach.err"

cleanup() {
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

python3 -m py_compile "${ROOT_DIR}/tools/mkdbg"

pushd "${TMP_DIR}" >/dev/null

python3 "${ROOT_DIR}/tools/mkdbg" init --name microkernel --port /dev/ttyUSB0 >/dev/null
python3 "${ROOT_DIR}/tools/mkdbg" attach \
  --dry-run \
  --break main \
  --command continue \
  --command bt \
  --batch > "${ATTACH_OUT}"

python3 - "${ATTACH_OUT}" <<'PY'
import sys
from pathlib import Path

text = Path(sys.argv[1]).read_text(encoding="utf-8")
checks = [
    "[mkdbg] openocd=openocd -f ",
    "[mkdbg] gdb=arm-none-eabi-gdb ",
    "-batch",
    "-ex 'break main'",
    "-ex continue",
    "-ex bt",
]
for item in checks:
    if item not in text:
        raise SystemExit(f"missing expected attach output: {item}")
PY

python3 "${ROOT_DIR}/tools/mkdbg" repo add tahoe --path . --attach-cmd "gdb build/tahoe.elf" >/dev/null
if python3 "${ROOT_DIR}/tools/mkdbg" attach tahoe --dry-run --break main > /dev/null 2> "${ATTACH_ERR}"; then
  echo "mkdbg_host_tests: expected attach_cmd override to reject scripted flags" >&2
  exit 1
fi

python3 - "${ATTACH_ERR}" <<'PY'
import sys
from pathlib import Path

text = Path(sys.argv[1]).read_text(encoding="utf-8")
needle = "attach_cmd cannot be combined with --break, --command, or --batch"
if needle not in text:
    raise SystemExit(f"missing expected error text: {needle}")
print("mkdbg_host_tests: OK")
PY

popd >/dev/null
