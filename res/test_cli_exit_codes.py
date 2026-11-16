import argparse
import re
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description="Check desktop launcher CLI exit codes")
    parser.add_argument("executable", type=Path)
    executable = str(parser.parse_args().executable.resolve(strict=True))

    for args, expected_status, expected_output in [
        (["--password-stdin", "--version"], 1, rb"Usage: rustdesk --password-stdin"),
        (["--version"], 0, rb"\d+\.\d+\.\d+"),
    ]:
        # Keep stdin open and empty until exit, so an unexpected read times out.
        with subprocess.Popen(
            [executable, *args],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        ) as process:
            try:
                status = process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
                raise
            output = process.communicate()[0]
        if status != expected_status:
            raise AssertionError(
                "{}: expected exit {}, got {}; output: {!r}".format(
                    args, expected_status, status, output
                )
            )
        if re.search(expected_output, output) is None:
            raise AssertionError("{}: unexpected output: {!r}".format(args, output))
        print("{}: exit {} OK".format(" ".join(args), status))


if __name__ == "__main__":
    main()
