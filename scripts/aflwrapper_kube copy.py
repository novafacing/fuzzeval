"""
AFLplusplus wrapper for fuzzing.
"""
from argparse import ArgumentParser
from datetime import datetime
from os import getenv, listdir, makedirs
from random import randint
from re import search
from shutil import rmtree, copytree, copyfile
from typing import Any, Dict, List, Tuple
from pathlib import Path
from uuid import uuid1
from subprocess import CalledProcessError, TimeoutExpired, run, call
from multiprocessing import Process
from time import sleep
from tqdm import tqdm
from json import load
import logging

l = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler("debug.log"), logging.StreamHandler()],
)


def ld_library_path(args: List[str]) -> str:
    """
    Get the LD_LIBRARY_PATH environment variable for a given binary.
    """
    return str(Path(args[0]).parent.resolve())


def binary_path_info(binary: str) -> Tuple[str, str]:
    """
    Get the binary path and corpus path.
    """
    bpath = Path(binary).resolve()
    # print(f"Getting binary and corpus path from {bpath}: {list(bpath.parents)}")

    b = bpath.parents[0].name
    c = bpath.parents[1].name
    # print(f"Got courpus, binary: {c}, {b}")
    assert str(b) and str(c), "Could not get binary and corpus path."
    return str(b), str(c)


def test_bin(seed: str, args: List[str]) -> bool:
    """
    Test the given binary with the given arguments.
    """

    # print(f"Testing binary with arguments '{args}'")
    assert Path(seed).is_dir(), "Seed directory does not exist."

    for seed_corpus in Path(seed).iterdir():
        print(f"Testing seed corpus: {seed_corpus}")
        for seed_path in seed_corpus.iterdir():
            if not seed_path.is_file():
                continue
            try:
                res = run(
                    args,
                    input=seed_path.read_bytes(),
                    env={"LD_LIBRARY_PATH": ld_library_path(args)},
                    capture_output=True,
                )
            except CalledProcessError as e:
                print(f"{e}:\n STDOUT: {res.stdout}\nSTDERR: {res.stderr}")
                return False
    return True


def minimize_seeds(
    afl_path: str,
    seed_dir: str,
    args: List[str],
    output_dir: str,
    seed_extension: str = "",
) -> str:
    """
    Run optimin on the seed directory and return the minimized seed directory.
    """
    print(f"Minimizing seeds in {seed_dir}")

    if Path(seed_dir).name.endswith("minimized"):
        return ""

    if Path(seed_dir).name == "empty":
        binary, corpus = binary_path_info(args[0])

        output_seed_dir_path = (
            Path(output_dir) / corpus / binary / (Path(seed_dir).name)
        )

        rmtree(output_seed_dir_path, ignore_errors=True)
        output_seed_dir_path.mkdir(parents=True, exist_ok=True)

        emptyfile = output_seed_dir_path / "empty.raw"
        with open(emptyfile, "wb") as f:
            f.write(b"\x00" * 1024)

        return str(output_seed_dir_path)

    else:

        binary, corpus = binary_path_info(args[0])

        minimized_seed_dir_path = (
            Path(output_dir) / corpus / binary / (Path(seed_dir).name + "_minimized")
        )

        rmtree(minimized_seed_dir_path, ignore_errors=True)
        minimized_seed_dir_path.mkdir(parents=True, exist_ok=True)
        minimized_seed_dir = str(minimized_seed_dir_path)

        for seedfile in Path(seed_dir).iterdir():
            if not seedfile.name.endswith(seed_extension):
                seedfile.unlink()

        try:
            run(
                f"{str(Path(afl_path).with_name('utils') / 'optimin' / 'optimin')} -Q -f -i {seed_dir} -o {minimized_seed_dir} -- {' '.join(args)}",
                shell=True,
                check=True,
                env={
                    "PATH": f"{str(Path(afl_path).parent)}:{getenv('PATH')}",
                    "LD_LIBRARY_PATH": ld_library_path(args),
                },
            )
        except CalledProcessError:
            print("Minimizing seeds failed.. this usually indicates a broken binary..")
            return "ERROR"
        return minimized_seed_dir


def run_wrapper(*args: List[Any], **kwargs: Dict[str, Any]) -> None:
    """
    Wrapper for run
    """
    global count
    r = None
    try:
        r = run(*args, **kwargs)
    except TimeoutExpired as e:
        return

    if r.returncode != 0:
        # print(f"FUZZER HAS CRASHED")
        print(
            f"\nCommand {args[0]} exited with:\nSTDOUT: {r.stdout}\nSTDERR: {r.stderr}\n"
        )
        exit(r.returncode)


def afl_whatsup(afl_path: str, output_dir: str) -> str:
    """
    Run afl-whatsup and return the output.
    """
    afl_whatsup_path = str(Path(afl_path).with_name("afl-whatsup").resolve())

    return run(
        f"{afl_whatsup_path} -s {output_dir}", shell=True, capture_output=True
    ).stdout.decode("utf-8")


def run_afl(
    afl_path: str, seed: str, output_dir: str, timeout: int, args: List[str]
) -> Tuple[List[Process], str]:
    """
    Run AFLplusplus with the given arguments.
    """

    assert Path(afl_path).is_file(), "afl-fuzz not found at {}".format(afl_path)
    assert Path(seed).is_dir(), "Seed directory does not exist."

    print(f"Fuzzing with arguments '{args}'")

    syncid = f"{uuid1()}"[:4]
    afl_seed = f"{randint(0, 99999)}"

    binary, corpus = binary_path_info(args[0])

    output_dir_path = (
        Path(output_dir) / corpus / binary / (syncid + "-" + Path(seed).name)
    )
    output_dir_path.mkdir(parents=True, exist_ok=True)

    output_dir = str(output_dir_path.resolve())

    main_core_cmd = (
        f"{afl_path} -M {syncid}-main -Q -s {afl_seed} -i {seed} -o {output_dir} -V {timeout * 60} "
        f"-- {' '.join(args)}"
    )
    cmplog_core_cmd = (
        f"{afl_path} -S {syncid}-clog -c 0 -l 2AT -Q -s {afl_seed} -i {seed} -o {output_dir} -V {timeout * 60} "
        f"-- {' '.join(args)}"
    )
    frida_core_cmd = (
        f"{afl_path} -S {syncid}-frida -O -s {afl_seed} -i {seed} -o {output_dir} -V {timeout * 60} "
        f"-- {' '.join(args)}"
    )
    qasan_core_cmd = (
        f"{afl_path} -S {syncid}-qasan -Q -s {afl_seed} -i {seed} -o {output_dir} -V {timeout * 60} "
        f"-- {' '.join(args)}"
    )

    coreprocs = []

    for core in [main_core_cmd, cmplog_core_cmd, frida_core_cmd, qasan_core_cmd]:
        print(f"Running fuzzer core: {core}")

        p = Process(
            target=run_wrapper,
            args=(core,),
            kwargs={
                "shell": True,
                "capture_output": True,
                "env": {"LD_LIBRARY_PATH": ld_library_path(args)},
            },
        )

        p.start()
        coreprocs.append(p)

    return coreprocs, output_dir


class EarlyExitException(Exception):
    pass


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument(
        "-t", "--timeout", type=int, default=1, help="Timeout in minutes"
    )
    parser.add_argument(
        "-a", "--afl-path", type=str, required=True, help="Path to afl-fuzz"
    )
    parser.add_argument(
        "-i",
        "--index",
        type=str,
        required=True,
        help="Kubernetes' job completion index ($JOB_COMPLETION_INDEX)",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        type=str,
        required=True,
        help="Path to the top-level output directory.",
    )
    parser.add_argument(
        "-e",
        "--seed-extension",
        type=str,
        default="",
        help="Extension to use for seeds, if specified only seeds with this extension will be used.",
    )
    parsed_args = parser.parse_args()

    # ---------- PREP PHASE ----------

    print(f"JOB_COMPLETION_INDEX = {parsed_args.index}")

    log_dir = Path("/shared/frqmod/logs/")
    if not log_dir.exists():
        # this is our only real failure case, this not existing usually means nothing else will work lol
        print(f"ERROR: Failed to stat log directory '{log_dir}'\nExiting..")
        exit(-1)

    mapping_path = Path("/shared/frqmod/mappings.json")
    if not mapping_path.exists():
        with open(Path(f"{log_dir}/{parsed_args.index}_log_FAILED"), "w+") as log_file:
            log_file.write(
                f"ERROR: Unable to stat mappings file '{mapping_path}'. Did you generate it?\n"
            )
        exit(0)

    index_to_binary = {}
    with open(mapping_path) as f:
        index_to_binary = load(f)
    if not index_to_binary:
        with open(Path(f"{log_dir}/{parsed_args.index}_log_FAILED"), "w+") as log_file:
            log_file.write(
                f"ERROR: Unable to parse mappings file '{mapping_path}'. Is it generated correctly?\n"
            )
        exit(0)

    target_binary = index_to_binary[parsed_args.index].split("/")[-1]
    print(f"Target Binary: {target_binary}")
    targz_path = Path(f"/shared/frqmod/tars/{target_binary}.tar.gz")

    if not targz_path.exists():
        with open(Path(f"{log_dir}/{parsed_args.index}_log_FAILED"), "w+") as log_file:
            log_file.write(
                f"ERROR: Unable to locate binary gzip '{mapping_path}'. Does it exist?\n"
            )
        exit(0)

    makedirs("/corpus/build/cgc/")
    copyfile(targz_path, f"/corpus/build/cgc/{target_binary}.tar.gz")
    call(
        [
            "tar",
            "xf",
            f"/corpus/build/cgc/{target_binary}.tar.gz",
            "-C",
            "/corpus/build/cgc/",
        ]
    )

    seed_dir = Path(f"/corpus/build/cgc/{target_binary}/seeds/")
    binary_path = f"/corpus/build/cgc/{target_binary}/{target_binary}"
    coreprocs = []
    outdirs = []
    min_seed_dirs = []
    for seed_path in list(seed_dir.iterdir()):
        for p in seed_path.rglob("**/*"):
            if p.is_file():
                p.chmod(0o777)
            elif p.is_dir():
                p.chmod(0o777)

        min_seed_dir = minimize_seeds(
            parsed_args.afl_path,
            str(seed_path),
            [binary_path],
            parsed_args.output_dir,
            parsed_args.seed_extension,
        )

        if min_seed_dir == "ERROR":
            with open(
                Path(f"{log_dir}/{parsed_args.index}_log_FAILED"), "w+"
            ) as log_file:
                log_file.write(
                    f"ERROR: Binary failed to minimize seeds. Does the binary work with a generated seed?\n"
                )
            exit(0)

        if not min_seed_dir:
            continue
        else:
            print(listdir(min_seed_dir))

        for p in Path(min_seed_dir).rglob("**/*"):
            if p.is_file():
                p.chmod(0o777)
            elif p.is_dir():
                p.chmod(0o777)

        min_seed_dirs.append(min_seed_dir)

        cores, outdir = run_afl(
            parsed_args.afl_path,
            min_seed_dir,
            parsed_args.output_dir,
            parsed_args.timeout,
            [binary_path],
        )
        coreprocs.extend(cores)
        outdirs.append(outdir)

    sleep(10)
    crashed_count = 0
    try:
        for i in range(parsed_args.timeout * 60):
            ncoreprocs = []
            for p in coreprocs:
                if not p.is_alive():
                    print(f"Fuzzer core exited: {p.pid} EXIT CODE: {p.exitcode}")
                    if p.exitcode != 0:
                        crashed_count += 1
                        print(f"FUZZER CRASHED. CRASH COUNT: {crashed_count}")
                    coreprocs.remove(p)
                    if not coreprocs:
                        print("All fuzzer cores exited.")
                        break
                else:
                    ncoreprocs.append(p)

            if crashed_count == 8:
                # okay we have no fuzzers alive
                raise EarlyExitException

            # perform a one time check at 5%
            if i == int(parsed_args.timeout * 60 * 0.05):
                print("onetime check for fuzzer crash..", i)
                if not ncoreprocs:
                    raise EarlyExitException
            coreprocs = ncoreprocs
            sleep(1)
    except KeyboardInterrupt:
        print(
            "Caught KeyboardInterrupt, terminating fuzzer cores. Please don't CTRL+C!"
        )
        for p in coreprocs:
            p.terminate()
    except EarlyExitException:
        print("All the fuzzers crashed..")
        with open(Path(f"{log_dir}/{parsed_args.index}_log_FAILED"), "w+") as log_file:
            log_file.write(f"ERROR: ALL FUZZERS DIED. {target_binary}\n")
        exit(0)

    print("Timeout finished. Waiting for fuzzers to exit. Please don't CTRL+C!")

    for core in coreprocs:
        core.terminate()

    print("Chmodding output directories to 755.")

    for outdir in outdirs:
        for pth in Path(outdir).rglob("**/*"):
            pth.chmod(0o755)

    print("Removing minimized seeds.")
    for min_seed_dir in min_seed_dirs:
        rmtree(min_seed_dir)

    sleep(5)
    print(["tar", "-cf", f"{parsed_args.index}_{target_binary}.tar.gz", "/results"])
    print(
        ["cp", f"{parsed_args.index}_{target_binary}.tar.gz", "/shared/frqmod/results/"]
    )
    call(["tar", "-cf", f"{parsed_args.index}_{target_binary}.tar.gz", "/results"])
    call(
        ["cp", f"{parsed_args.index}_{target_binary}.tar.gz", "/shared/frqmod/results/"]
    )

    with open(Path(f"{log_dir}/{parsed_args.index}_log_SUCCEEDED"), "w+") as log_file:
        log_file.write(f"{target_binary}\n")
