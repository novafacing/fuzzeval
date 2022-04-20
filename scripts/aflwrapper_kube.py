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

# config value:
SHARED_MOUNT_POINT = "/shared/frqmod"

l = logging.Logger("reface_fuzzer")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()],
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
        l.info(f"Testing seed corpus: {seed_corpus}")
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
                l.info(f"{e}:\n STDOUT: {res.stdout}\nSTDERR: {res.stderr}")
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
            l.info("Minimizing seeds failed.. this usually indicates a broken binary..")
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
        l.info(
            f"\nCommand {args[0]} exited with:\nSTDOUT:\n{r.stdout.decode('utf-8')}\nSTDERR: {r.stderr}\n"
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

    l.info(f"Fuzzing with arguments '{args}'")

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
        l.info(f"Running fuzzer core: {core}")

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

    # first attempt to get our log file running
    fh = logging.FileHandler(f"{SHARED_MOUNT_POINT}/logs/{parsed_args.index}_log")
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    fh.setFormatter(formatter)
    l.addHandler(fh)

    l.info(f"Starting Kubernetes ReFace Distributed Fuzzer™..")
    l.info(f"JOB_COMPLETION_INDEX = {parsed_args.index}\n")

    mapping_path = Path(f"{SHARED_MOUNT_POINT}/mappings.json")
    if not mapping_path.exists():
        l.error(f"Mapping file '{mapping_path}' not found!")
        l.info("Exiting..")
        exit(0)

    index_to_binary = {}
    with open(mapping_path) as f:
        index_to_binary = load(f)
    if not index_to_binary:
        l.error(
            f"Unable to parse mappings file '{mapping_path}'. Is it generated correctly?\n"
        )
        l.info("Exiting..")
        exit(0)

    l.info(f"Succesfully parsed mapping file '{mapping_path}'")

    target_binary = index_to_binary[parsed_args.index].split("/")[-1]
    l.info(f"[!] Target Binary: {target_binary}")
    targz_path = Path(f"{SHARED_MOUNT_POINT}/tars/{target_binary}.tar.gz")
    l.info(f"Attempting to grab binary gzip '{targz_path}'..")

    if not targz_path.exists():
        l.error(f"Unable to parse locate binary gzip '{targz_path}'. Does it exist?\n")
        l.info("Exiting..")
        exit(0)

    l.info(f"\t-> Found!")

    if not Path("/target_binary/").exists():
        l.info("Making /target_binary/ folder..")
        makedirs("/target_binary/")

    l.info(f"Copying '{targz_path}' to /target_binary/")
    copyfile(targz_path, f"/target_binary/{target_binary}.tar.gz")
    l.info("Unzipping..")
    call(
        [
            "tar",
            "xf",
            f"/target_binary/{target_binary}.tar.gz",
            "-C",
            "/target_binary/",
        ]
    )

    l.info("Done!\n")

    seed_dir = Path(f"/target_binary/{target_binary}/seeds/")
    l.info(f"Seed Directory: {seed_dir}")

    binary_path = f"/target_binary/{target_binary}/{target_binary}"
    l.info(f"Binary Path: {binary_path}")

    if not Path(binary_path).exists():
        l.error(f"Unable to locate binary '{binary_path}'. Does it exist?\n")
        l.info("Exiting..")
        exit(0)

    coreprocs = []
    outdirs = []
    min_seed_dirs = []
    for seed_path in reversed(list(seed_dir.iterdir())):
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
            l.error(f"[!] Unable to minimize seeds! Does the binary.. work?\n")
            l.info("Exiting..")
            exit(0)

        if not min_seed_dir:
            continue
        else:
            l.info(f"Seeds: {listdir(min_seed_dir)}")

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
    try:
        for i in range(parsed_args.timeout * 60):
            ncoreprocs = []
            for p in coreprocs:
                if not p.is_alive():
                    l.info(f"Fuzzer core exited: {p.pid} EXIT CODE: {p.exitcode}")
                    coreprocs.remove(p)
                    if not coreprocs:
                        l.info("All fuzzer cores exited.")
                        break
                else:
                    ncoreprocs.append(p)

            # perform a one time check at 5%
            if i == 60:
                l.info("Checking fuzzers at 60 seconds in for crashes..", i)
                if not ncoreprocs:
                    raise EarlyExitException

            coreprocs = ncoreprocs
            sleep(1)
    except KeyboardInterrupt:
        l.info(
            "Caught KeyboardInterrupt, terminating fuzzer cores. Please don't CTRL+C!"
        )
        for p in coreprocs:
            p.terminate()
    except EarlyExitException:
        l.critical("!! [CRASH] ALL FUZZERS HAVE CRASHED/EXITED EARLY !!")
        l.info("Exiting..")
        exit(0)

    l.info("Timeout finished. Waiting for fuzzers to exit. Please don't CTRL+C!")

    for core in coreprocs:
        core.terminate()

    l.info("Chmodding output directories to 755.")

    for outdir in outdirs:
        for pth in Path(outdir).rglob("**/*"):
            pth.chmod(0o755)

    l.info("Removing minimized seeds.")
    for min_seed_dir in min_seed_dirs:
        rmtree(min_seed_dir)

    sleep(5)
    l.info("Offloading fuzzer results to shared path..")
    l.info(["tar", "-cf", f"{parsed_args.index}_{target_binary}.tar.gz", "/results"])
    l.info(
        [
            "cp",
            f"{parsed_args.index}_{target_binary}.tar.gz",
            "{SHARED_MOUNT_POINT}/results/",
        ]
    )
    call(["tar", "-cf", f"{parsed_args.index}_{target_binary}.tar.gz", "/results"])
    call(
        [
            "cp",
            f"{parsed_args.index}_{target_binary}.tar.gz",
            "{SHARED_MOUNT_POINT}/results/",
        ]
    )

    l.info("Success! Exiting..")
