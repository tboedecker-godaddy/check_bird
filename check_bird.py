#!/usr/bin/env python3
# pylint: disable=global-statement,global-variable-not-assigned,too-few-public-methods

"""NRPE compatible monitoring script for BIRD.

https://bird.network.cz/
"""

import argparse
import enum
import ipaddress
import re
import shlex
import subprocess
import sys
import typing
import dateutil.parser


TIPAddr = typing.Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
TRouteTpl = typing.Tuple[TIPAddr, typing.Set[TIPAddr]]
TRouteList = typing.List[TRouteTpl]

BIRDC_PATH = '/sbin/birdc'
BIRDC_STATUS_OK = 'Daemon is up and running'
RE_ROUTE_BEGIN = re.compile(r'^(?P<route>.*?)\/(?P<cidr>32|128)')


class RunCommandError(Exception):
    """thrown by run()/run_proc() if the command exited unexpectly."""


class Exitcode(enum.Enum):
    """Exitcode enum accoring to NRPE spec."""

    OK = 0
    WARNING = 1
    CRITICAL = 2
    UNKNOWN = 3


EXITCODE = Exitcode.UNKNOWN

OKS = []
CRITICALS = []
WARNINGS = []
UNKNOWNS = []


def _set_exitcode(code: Exitcode):
    global EXITCODE
    if code == Exitcode.CRITICAL:
        EXITCODE = code
    elif code == Exitcode.WARNING and EXITCODE != Exitcode.CRITICAL:
        EXITCODE = code
    elif code == Exitcode.UNKNOWN and EXITCODE not in (Exitcode.CRITICAL, Exitcode.WARNING):
        EXITCODE = code
    elif code == Exitcode.OK and EXITCODE not in (Exitcode.CRITICAL, Exitcode.WARNING, Exitcode.UNKNOWN):
        EXITCODE = code


def _set_exitmsg(msg: str, code: Exitcode):
    global CRITICALS
    global WARNINGS
    global UNKNOWNS
    if code == Exitcode.CRITICAL:
        CRITICALS.append(msg)
    elif code == Exitcode.WARNING:
        WARNINGS.append(msg)
    elif code == Exitcode.OK:
        OKS.append(msg)
    else:
        UNKNOWNS.append(msg)


def _exit() -> None:
    global EXITCODE
    global CRITICALS
    global WARNINGS
    global UNKNOWNS
    global OKS
    print(f"{EXITCODE.name.upper()}: {';'.join(CRITICALS + WARNINGS + UNKNOWNS + OKS)}", file=sys.stdout, flush=True)
    sys.exit(EXITCODE.value)


class BirdBFDSession():
    """BIRD BFD Session contextualized class."""

    def __init__(self, line: str):
        """Init."""
        fields = re.sub('[ \t]+', ' ', line).split(' ')
        self.ip_addr = ipaddress.ip_address(fields[0])
        self.iface = fields[1].lower()
        self.state = fields[2].lower()
        self.since = dateutil.parser.parse(f'{fields[3]} {fields[4]}')
        self.interval = float(fields[5])
        self.timeout = float(fields[6])


class BirdProtocol():
    """BIRD Protocol contextualized class."""

    def __init__(self, line: str):
        """Init."""
        fields = re.sub('[ \t]+', ' ', line).split(' ')
        self.name = fields[0]
        self.proto = fields[1].lower()
        self.table = fields[2].lower()
        self.state = fields[3].lower()
        self.since = dateutil.parser.parse(f'{fields[4]} {fields[5]}')
        self.info = ' '.join(fields[6:])


def _cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        __file__,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument(
        '--protocols-warn', '-p',
        metavar='PATTERN-LIST',
        dest='protocols_warn',
        help='Warning if any of the given protocols is down (comma separated list)',
    )

    parser.add_argument(
        '--protocols-crit', '-P',
        metavar='PATTERN-LIST',
        dest='protocols_crit',
        help='Critical if any of the given protocols is down (comma separated list)',
    )

    parser.add_argument(
        '--bfd-warn', '-b',
        metavar='IPADDR-LIST',
        dest='bfd_warn',
        help='Warning if any of the given BFD sessions is down (comma separated list)',
    )

    parser.add_argument(
        '--bfd-crit', '-B',
        metavar='IPADDR-LIST',
        dest='bfd_crit',
        help='Critical if any of the given BFD sessions is down (comma separated list)',
    )

    parser.add_argument(
        '--export-table', '-t',
        metavar='TABLE-NAME',
        dest='export_table',
        help='BIRD table name used for exporting routes',
    )

    parser.add_argument(
        '--export-table-base', '-T',
        metavar='TABLE-BASE',
        dest='export_table_base',
        help="BIRD table name base used for exporting routes. "
             "(both suffixes '4' and '6' will be taken into consideration)",
    )

    parser.add_argument(
        '--table-min', '-e',
        metavar='NUM',
        type=int,
        dest='table_min',
        help='Warning if collected less than NUM routes in the selected export table.',
    )

    parser.add_argument(
        '--table-max', '-E',
        metavar='NUM',
        type=int,
        dest='table_max',
        help='Warning if collected more than NUM routes in the selected export table.',
    )

    parser.add_argument(
        '--check-duplicates', '-D',
        action='store_true',
        dest='check_duplicates',
        help='Warning if there are duplicate routes in the selected export table.',
    )

    parser.add_argument(
        '--print-duplicates', '-d',
        action='store_true',
        dest='print_duplicates',
        help='Print duplicate routes in the selected export table.',
    )

    return parser


def _run(cmdline: str, stdin=None, raise_err=True, expected_rc=0) -> str:
    stdin = stdin or subprocess.PIPE
    try:
        proc = subprocess.run(
            shlex.split(cmdline),
            universal_newlines=True,
            stdin=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
        if raise_err and proc.returncode != expected_rc:
            raise RunCommandError(proc.stderr)
        return proc.stdout or ''
    except subprocess.CalledProcessError as ex:
        _set_exitcode(Exitcode.UNKNOWN)
        _set_exitmsg(f"query failed: {ex}", Exitcode.UNKNOWN)
        if raise_err:
            _exit()
    return ''


def _bird_status() -> bool:
    global EXITCODE
    try:
        output = _run(f'{BIRDC_PATH} show status')
        statusline = output.strip("\n").splitlines()[-1]
        if BIRDC_STATUS_OK in statusline:
            _set_exitmsg(BIRDC_STATUS_OK, Exitcode.OK)
            EXITCODE = Exitcode.OK
            return True
        raise RunCommandError()
    except RunCommandError:
        _set_exitcode(Exitcode.CRITICAL)
        _set_exitmsg('BIRD is NOT running', Exitcode.CRITICAL)
        return False


def _bird_protocols() -> typing.Dict[str, BirdProtocol]:
    protocols = {}
    output = _run(f'{BIRDC_PATH} show protocols')
    for line in output.splitlines()[2:]:
        proto = BirdProtocol(line)
        protocols[proto.name] = proto
    return protocols


def _bird_bfd_sessions() -> typing.Dict[TIPAddr, BirdBFDSession]:
    sessions = {}
    output = _run(f'{BIRDC_PATH} show bfd sessions')
    for line in output.splitlines()[3:]:
        session = BirdBFDSession(line)
        sessions[session.ip_addr] = session
    return sessions


def _parse_bird_routes(bird_output: str) -> TRouteList:
    routes = {}
    current: typing.Union[TRouteTpl, typing.Tuple[None, None]] = (None, None)
    for line in bird_output.strip("\n").splitlines()[2:]:
        m_begin = RE_ROUTE_BEGIN.match(line)
        if m_begin:
            _route = m_begin.groupdict().get('route')
            assert _route is not None
            route = ipaddress.ip_address(_route)
            nexthops = set()
            routes[route] = nexthops
            current = (route, nexthops)
        else:
            if line.startswith('\tBGP.next_hop'):
                assert current != (None, None)
                _, _nexthop = line.strip().split(': ', 2)
                assert _nexthop not in ('', None)
                nexthop = ipaddress.ip_address(_nexthop)
                _, rt_nhs = typing.cast(TRouteTpl, current)
                rt_nhs.add(nexthop)

    # return [(k, v) for k,v in routes.items()]
    return list(routes.items())


def _bird_routes_in_tables(tables: typing.List[str]) -> TRouteList:
    return [s for t in tables for s in _parse_bird_routes(_run(f'{BIRDC_PATH} show route all table {t}'))]


def _duplicate_routes(route_list: TRouteList) -> TRouteList:
    return sorted([x for x in route_list if len(x[1]) > 1], key=lambda x: int(x[0]))


def _print_route_list(route_list: TRouteList) -> None:
    for rtpl in route_list:
        route = rtpl[0]
        nexthops = sorted(list(rtpl[1]), key=int)
        if route.version == 4:
            print(f"{str(route):<15s} | {','.join([str(x) for x in nexthops])}")
        elif route.version == 6:
            print(f"{str(route):<36s} | {','.join([str(x) for x in nexthops])}")


def _ensure_protocols(
    pattern_list: typing.List[str],
    protocols: typing.Dict[str, BirdProtocol],
    code: Exitcode
) -> None:
    for pattern in pattern_list:
        found = False
        pattern_re = re.compile(re.sub('[*]+', '[a-zA-Z0-9_]*', pattern))

        for name, proto in protocols.items():
            if pattern_re.match(name):
                found = True
                if proto.state != 'up':
                    _set_exitcode(code)
                    _set_exitmsg(f"Protocol {proto.name} is not up", code)
        if not found:
            _set_exitcode(code)
            _set_exitmsg(f"Protocol {pattern} not found", code)


def _ensure_bfd_sessions(
    addr_list: typing.List[str],
    bfd_sessions: typing.Dict[TIPAddr, BirdBFDSession],
    code: Exitcode
) -> None:
    for addr in addr_list:
        ip_addr = ipaddress.ip_address(addr)
        if ip_addr not in bfd_sessions.keys():
            _set_exitcode(code)
            _set_exitmsg(f"BFD Session to {ip_addr} not found", code)
        else:
            if bfd_sessions[ip_addr].state != 'up':
                _set_exitcode(code)
                _set_exitmsg(f"BFD Session to {ip_addr} is not up", code)


def _check_routes(args: argparse.Namespace, routes: TRouteList) -> None:
    num_routes = len(routes)
    if args.table_min is not None and num_routes < args.table_min:
        _set_exitcode(Exitcode.WARNING)
        _set_exitmsg(f"Tables {args.export_tables} only contain {num_routes} routes, "
                     f"expected at least {args.table_min}", Exitcode.WARNING)
    if args.table_max is not None and num_routes > args.table_max:
        _set_exitcode(Exitcode.WARNING)
        _set_exitmsg(f"Tables {args.export_tables} contain {num_routes} routes, "
                     f"expected at most {args.table_max}", Exitcode.WARNING)


def _check_protocols(args: argparse.Namespace, protocols: typing.Dict[str, BirdProtocol]) -> None:
    if args.protocols_warn is not None:
        _ensure_protocols(args.protocols_warn.split(','), protocols, Exitcode.WARNING)
    if args.protocols_crit is not None:
        _ensure_protocols(args.protocols_crit.split(','), protocols, Exitcode.CRITICAL)


def _check_bfd_sessions(args: argparse.Namespace, bfd_sessions: typing.Dict[TIPAddr, BirdBFDSession]) -> None:
    if args.bfd_warn is not None:
        _ensure_bfd_sessions(args.bfd_warn.split(','), bfd_sessions, Exitcode.WARNING)
    if args.bfd_crit is not None:
        _ensure_bfd_sessions(args.bfd_crit.split(','), bfd_sessions, Exitcode.CRITICAL)


def _check_duplicate_routes(args: argparse.Namespace, routes: TRouteList) -> None:
    if args.print_duplicates or args.check_duplicates:
        duplicate_routes = _duplicate_routes(routes)
        if duplicate_routes:
            if args.print_duplicates:
                print(f"Found {len(duplicate_routes)} duplicate routes:", file=sys.stderr, flush=True)
                _print_route_list(duplicate_routes)
            _set_exitcode(Exitcode.WARNING)
            _set_exitmsg(f"Found {len(duplicate_routes)} duplicate routes in tables {args.export_tables}",
                         Exitcode.WARNING)
        else:
            if args.print_duplicates:
                print("No duplicate routes found.", file=sys.stderr, flush=True)


def main() -> None:
    """."""
    global EXITCODE
    cli_parser = _cli_parser()
    args = cli_parser.parse_args()

    if args.export_table is None and args.export_table_base is None:
        for table_required_arg in ('table_min', 'table_max', 'check_duplicates', 'print_duplicates'):
            if getattr(args, table_required_arg) not in (None, False):
                msg = f"argument '{table_required_arg}' requires to specify the export table."
                print(f"ERROR: {msg}",
                      file=sys.stderr, flush=True)
                cli_parser.print_help()
                _set_exitcode(Exitcode.UNKNOWN)
                _set_exitmsg(msg, Exitcode.UNKNOWN)
                _exit()

    if args.export_table_base is not None:
        args.export_tables = [f"{args.export_table_base}4", f"{args.export_table_base}6"]
    else:
        args.export_tables = [args.export_table]

    protocols = {}
    bfd_sessions = {}
    routes = []

    # check that bird is up and running, this will already set the exitcode and exitmsg if needed
    if not _bird_status():
        _exit()

    # fetch routes from the given export_table only if needed
    routes_required = ('export_table', 'export_table_base', 'check_duplicates', 'print_duplicates')
    if any(getattr(args, x) not in (None, False) for x in routes_required):
        routes = _bird_routes_in_tables(args.export_tables)

    # fetch protocols only if needed
    protocols_required = ('protocols_warn', 'protocols_crit')
    if any(getattr(args, x) not in (None, False) for x in protocols_required):
        protocols = _bird_protocols()

    # fetch bfd sessions only if needed
    bfd_sessions_required = ('bfd_warn', 'bfd_crit')
    if any(getattr(args, x) not in (None, False) for x in bfd_sessions_required):
        bfd_sessions = _bird_bfd_sessions()

    # proceed with the actual checks
    _check_routes(args, routes)
    _check_protocols(args, protocols)
    _check_bfd_sessions(args, bfd_sessions)
    _check_duplicate_routes(args, routes)

    _exit()


if __name__ == '__main__':
    main()
