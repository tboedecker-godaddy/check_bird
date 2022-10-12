#!/usr/bin/env python3

import argparse
import dateutil.parser
import enum
import ipaddress
import re
import shlex
import subprocess
import sys
import typing


t_IPAddr = typing.Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
t_RouteTpl = typing.Tuple[t_IPAddr, typing.Set[t_IPAddr]]
t_RouteList = typing.List[t_RouteTpl]

BIRDC_PATH = '/sbin/birdc'
BIRDC_STATUS_OK = 'Daemon is up and running'
RE_ROUTE_BEGIN = re.compile(r'^(?P<route>.*?)\/(?P<cidr>32|128)')


class RunCommandError(Exception):
    """ thrown by run()/run_proc() if the command exited unexpectly """


class Exitcode(enum.Enum):
    ok = 0
    warning = 1
    critical = 2
    unknown = 3


exitcode = Exitcode.ok
exitmsg = ''

criticals = []
warnings = []
unknowns = []


def _set_exitcode(code: Exitcode):
    global exitcode
    if (code.value > exitcode.value) or (code == Exitcode.critical):
        exitcode = code

def _set_exitmsg(msg: str, code: Exitcode):
    global exitmsg
    global criticals
    global warnings
    global unknowns
    if code == Exitcode.critical:
        criticals.append(msg)
    elif code == Exitcode.warning:
        warnings.append(msg)
    elif code == Exitcode.unknown:
        unknowns.append(msg)
    else:
        exitmsg = f'{exitmsg};{msg}'


class BirdBFDSession():
    def __init__(self, line: str):
        fields = re.sub('[ \t]+', ' ', line).split(' ')
        self.ip_addr = ipaddress.ip_address(fields[0])
        self.iface = fields[1].lower()
        self.state = fields[2].lower()
        self.since = dateutil.parser.parse(f'{fields[3]} {fields[4]}')
        self.interval = float(fields[5])
        self.timeout = float(fields[6])


class BirdProtocol():
    def __init__(self, line: str):
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
        if raise_err:
            raise RunCommandError(repr(ex)) from ex
        else:
            pass
    return ''


def _bird_status() -> bool:
    global exitcode
    global exitmsg
    try:
        output = _run(f'{BIRDC_PATH} show status')
        statusline = output.strip("\n").splitlines()[-1]
        if BIRDC_STATUS_OK in statusline:
            exitmsg = BIRDC_STATUS_OK
            return True
        else:
            raise RunCommandError()
    except RunCommandError:
        exitcode = Exitcode.critical
        exitmsg = 'BIRD is NOT running'
        return False


def _bird_protocols() -> typing.Dict[str, BirdProtocol]:
    protocols = {}
    output = _run(f'{BIRDC_PATH} show protocols')
    for line in output.splitlines()[2:]:
        proto = BirdProtocol(line)
        protocols[proto.name] = proto
    return protocols


def _bird_bfd_sessions() -> typing.Dict[t_IPAddr, BirdBFDSession]:
    sessions = {}
    output = _run(f'{BIRDC_PATH} show bfd sessions')
    for line in output.splitlines()[3:]:
        session = BirdBFDSession(line)
        sessions[session.ip_addr] = session
    return sessions


def _parse_bird_routes(bird_output: str) -> t_RouteList:
    routes = {}
    current = None
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
                assert current is not None
                _, _nexthop = line.strip().split(': ', 2)
                assert _nexthop not in ('', None)
                nexthop = ipaddress.ip_address(_nexthop)
                current[1].add(nexthop)

    return [(k, v) for k,v in routes.items()]


def _bird_routes_in_table(table: str) -> t_RouteList:
    return _parse_bird_routes(_run(f'{BIRDC_PATH} show route all table {table}'))


def _duplicate_routes(route_list: t_RouteList) -> t_RouteList:
    return sorted([x for x in route_list if len(x[1]) > 1], key=lambda x: int(x[0]))


def _print_route_list(route_list: t_RouteList) -> None:
    for rtpl in route_list:
        route = rtpl[0]
        nexthops = sorted(list(rtpl[1]), key=lambda n: int(n))
        if route.version == 4:
            print(f"{str(route):<15s} | {','.join([str(x) for x in nexthops])}")
        elif route.version == 6:
            print(f"{str(route):<36s} | {','.join([str(x) for x in nexthops])}")


def _exit() -> None:
    global exitcode
    global exitmsg
    global criticals
    global warnings
    global unknowns
    print(f"{exitcode.name.upper()}: {';'.join(criticals + warnings + unknowns + [exitmsg])}", file=sys.stdout, flush=True)
    sys.exit(exitcode.value)


def _ensure_protocols(
    pattern_list: typing.List[str],
    protocols: typing.Dict[str, BirdProtocol],
    code: Exitcode
) -> None:
    for pattern in pattern_list:
        found = False
        pattern_re = re.compile(re.sub('[*]+', '[a-zA-Z0-9_]*', pattern))

        for k, v in protocols.items():
            if pattern_re.match(k):
                found = True
                if v.state != 'up':
                    _set_exitcode(code)
                    _set_exitmsg(f"Protocol {v.name} is not up", code)
        if not found:
            _set_exitcode(code)
            _set_exitmsg(f"Protocol {pattern} not found", code)


def _ensure_bfd_sessions(
    addr_list: typing.List[str],
    bfd_sessions: typing.Dict[t_IPAddr, BirdBFDSession],
    code: Exitcode
) -> None:
    for addr in addr_list:
        ip = ipaddress.ip_address(addr)
        if ip not in bfd_sessions.keys():
            _set_exitcode(code)
            _set_exitmsg(f"BFD Session to {ip} not found", code)
        else:
            if bfd_sessions[ip].state != 'up':
                _set_exitcode(code)
                _set_exitmsg(f"BFD Session to {ip} is not up", code)


def main() -> None:
    """ main entry point """
    global exitcode
    global exitmsg
    cli_parser = _cli_parser()
    args = cli_parser.parse_args()

    if args.export_table is None:
        for table_required_arg in ('table_min', 'table_max', 'check_duplicates', 'print_duplicates'):
            if getattr(args, table_required_arg) not in (None, False):
                msg = f"argument '{table_required_arg}' requires to specify the export table."
                print(f"ERROR: {msg}",
                      file=sys.stderr, flush=True)
                cli_parser.print_help()
                _set_exitcode(Exitcode.unknown)
                _set_exitmsg(msg, Exitcode.unknown)
                _exit()

    protocols = {}
    bfd_sessions = {}
    routes = []

    # check that bird is up and running, this will already set the exitcode and exitmsg if needed
    if not _bird_status():
        return

    # fetch routes from the given export_table only if needed
    routes_required = ('export_table', 'check_duplicates', 'print_duplicates')
    if any([getattr(args, x) not in (None, False) for x in routes_required]):
        routes = _bird_routes_in_table(args.export_table)

    # fetch protocols only if needed
    protocols_required = ('protocols_warn', 'protocols_crit')
    if any([getattr(args, x) not in (None, False) for x in protocols_required]):
        protocols = _bird_protocols()

    # fetch bfd sessions only if needed
    bfd_sessions_required = ('bfd_warn', 'bfd_crit')
    if any([getattr(args, x) not in (None, False) for x in bfd_sessions_required]):
        bfd_sessions = _bird_bfd_sessions()

    # proceed with the actual checks

    num_routes = len(routes)
    if args.table_min is not None and num_routes < args.table_min:
        _set_exitcode(Exitcode.warning)
        _set_exitmsg(f"Table {args.export_table} only contains {num_routes} routes, expected at least {args.table_min}", Exitcode.warning)
    if args.table_max is not None and num_routes > args.table_max:
        _set_exitcode(Exitcode.warning)
        _set_exitmsg(f"Table {args.export_table} contains {num_routes} routes, expected at most {args.table_max}", Exitcode.warning)

    if args.protocols_warn is not None:
        _ensure_protocols(args.protocols_warn.split(','), protocols, Exitcode.warning)
    if args.protocols_crit is not None:
        _ensure_protocols(args.protocols_crit.split(','), protocols, Exitcode.critical)

    if args.bfd_warn is not None:
        _ensure_bfd_sessions(args.bfd_warn.split(','), bfd_sessions, Exitcode.warning)
    if args.bfd_crit is not None:
        _ensure_bfd_sessions(args.bfd_crit.split(','), bfd_sessions, Exitcode.critical)

    if args.print_duplicates or args.check_duplicates:
        duplicate_routes = _duplicate_routes(routes)
        if duplicate_routes:
            if args.print_duplicates:
                print(f"Found {len(duplicate_routes)} duplicate routes:", file=sys.stderr, flush=True)
                _print_route_list(duplicate_routes)
            _set_exitcode(Exitcode.warning)
            _set_exitmsg(f"Found {len(duplicate_routes)} duplicate routes in table {args.export_table}", Exitcode.warning)
        else:
            if args.print_duplicates:
                print(f"No duplicate routes found.", file=sys.stderr, flush=True)
    _exit()


if __name__ == '__main__':
    main()
