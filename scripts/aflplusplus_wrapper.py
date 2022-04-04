"""
AFLplusplus wrapper for fuzzing.
"""
from argparse import ArgumentParser
from datetime import datetime
from os import getenv
from random import randint
from re import search
from shutil import rmtree
from typing import Any, Dict, List, Tuple
from pathlib import Path
from uuid import uuid1
from subprocess import CalledProcessError, TimeoutExpired, run
from multiprocessing import Process
from time import sleep
from tqdm import tqdm


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
                print(f"{e}: {e.stderr}")
                return False
    return True


def minimize_seeds(afl_path: str, seed_dir: str, args: List[str]) -> str:
    """
    Run optimin on the seed directory and return the minimized seed directory.
    """
    print(f"Minimizing seeds in {seed_dir}")
    if Path(seed_dir).name.endswith("minimized"):
        return ""
    minimized_seed_dir_path = (
        Path(seed_dir).with_name(f"{Path(seed_dir).name}_minimized").resolve()
    )
    rmtree(minimized_seed_dir_path, ignore_errors=True)
    minimized_seed_dir_path.mkdir(parents=True, exist_ok=True)
    minimized_seed_dir = str(minimized_seed_dir_path)
    run(
        f"{str(Path(afl_path).with_name('utils') / 'optimin' / 'optimin')} -Q -f -i {seed_dir} -o {minimized_seed_dir} -- {' '.join(args)}",
        shell=True,
        check=True,
        env={
            "PATH": f"{str(Path(afl_path).parent)}:{getenv('PATH')}",
            "LD_LIBRARY_PATH": ld_library_path(args),
        },
    )
    return minimized_seed_dir


def run_wrapper(*args: List[Any], **kwargs: Dict[str, Any]) -> None:
    """
    Wrapper for run
    """
    r = None
    try:
        r = run(*args, **kwargs)
    except TimeoutExpired as e:
        return
    except CalledProcessError as e:
        print(f"{e}: {r.stderr if r is not None else ''}")
        return


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
                "check": True,
                "env": {"LD_LIBRARY_PATH": ld_library_path(args)},
            },
        )

        p.start()
        coreprocs.append(p)

    return coreprocs, output_dir


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument(
        "-t", "--timeout", type=int, default=1, help="Timeout in minutes"
    )
    parser.add_argument(
        "-a", "--afl-path", type=str, required=True, help="Path to afl-fuzz"
    )
    parser.add_argument(
        "-s",
        "--seed-dir",
        type=str,
        required=False,
        default="",
        help="Path to the seed directory.",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        type=str,
        required=True,
        help="Path to the top-level output directory.",
    )
    parser.add_argument(
        "args",
        nargs="*",
        help="Arguments to the binary to fuzz, including the binary itself ex `/path/to/binary -arg1 -arg2`",
    )
    parsed_args = parser.parse_args()

    if not parsed_args.seed_dir:
        parsed_args.seed_dir = str(Path(parsed_args.args[0]).with_name("seeds"))

    if not parsed_args.args:
        raise ValueError("No arguments provided.")

    if not test_bin(parsed_args.seed_dir, parsed_args.args):
        raise ValueError("Binary test failed.")

    coreprocs = []
    outdirs = []
    for seed_path in list(Path(parsed_args.seed_dir).iterdir()):
        min_seed_dir = minimize_seeds(
            parsed_args.afl_path, str(seed_path), parsed_args.args
        )
        if not min_seed_dir:
            continue
        cores, outdir = run_afl(
            parsed_args.afl_path,
            min_seed_dir,
            parsed_args.output_dir,
            parsed_args.timeout,
            parsed_args.args,
        )
        coreprocs.extend(cores)
        outdirs.append(outdir)

    sleep(5)

    bars = list(
        map(
            lambda o: tqdm(desc=f"{o[1]}", position=o[0] + 1),
            zip(range(len(outdirs)), outdirs),
        )
    )

    try:
        for _ in tqdm(
            range(parsed_args.timeout * 60),
            desc="Waiting for fuzzers to finish",
            position=0,
            unit="s",
        ):
            ncoreprocs = []
            for p in coreprocs:
                if not p.is_alive():
                    print(f"Fuzzer core exited: {p.pid}")
                    coreprocs.remove(p)
                    if not coreprocs:
                        print("All fuzzer cores exited.")
                        break
                else:
                    ncoreprocs.append(p)

            for outdir, bar in zip(outdirs, bars):
                whatsup_res = afl_whatsup(parsed_args.afl_path, outdir)
                speed = int(search(r"Cumulative speed : (\d+)", whatsup_res).group(1))
                bar.update(speed)

            coreprocs = ncoreprocs
            sleep(1)
    except KeyboardInterrupt:
        print(
            "Caught KeyboardInterrupt, terminating fuzzer cores. Please don't CTRL+C!"
        )
        for p in coreprocs:
            p.terminate()

    print("Timeout finished. Waiting for fuzzers to exit. Please don't CTRL+C!")

    for core in coreprocs:
        core.terminate()

    print("Chmodding output directories to 755.")

    for outdir in outdirs:
        for pth in Path(outdir).rglob("**/*"):
            pth.chmod(0o755)
