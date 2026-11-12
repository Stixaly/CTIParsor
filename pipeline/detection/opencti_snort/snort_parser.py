"""Parser, sanitiser and serialiser for one Snort rule.

This is OpenCTI's copy of its Snort parser. README.md in this folder gives the
source, the licence and the local patches. `Parser` splits a rule string into a
header dict and an options dict, and raises ValueError or SyntaxError for the
input it refuses. `Sanitizer` normalises pcre values, and `SerializeRule`
writes a parsed rule back to text.

The parser checks option names against the keyword tables in snort_dicts.py,
and checks addresses and ports. It does not check the arguments of most
keywords. The TODO comments in this file and in snort_dicts.py mark the
places where that is so; README.md lists them."""
import collections
import ipaddress
import re
from typing import Any, Dict, List, Optional, Tuple, Union

from .snort_dicts import Dicts


class Parser:
    """
    this will take an array of lines and parse it and hand
    back a dictionary
    NOTE: if you pass an invalid rule to the parser,
    it will a raise ValueError.
    """

    def __init__(self, rule):
        self.dicts = Dicts()
        self.rule = rule
        self.header = self.parse_header()
        self.options = self.parse_options()
        self.validate_options(self.options)
        self.data = {"header": self.header, "options": self.options}
        self.all = self.data

    def __iter__(self):
        yield self.data

    def __getitem__(self, key):
        if key == "all":
            return self.data
        return self.data[key]

    @staticmethod
    def actions(action: str) -> str:
        """Return `action` when it is a Snort rule action, and raise ValueError otherwise.

        The accepted actions are alert, log, pass, activate, dynamic, drop, reject and sdrop."""
        actions = {
            "alert",
            "log",
            "pass",
            "activate",
            "dynamic",
            "drop",
            "reject",
            "sdrop",
        }

        if action in actions:
            return action
        msg = f"Invalid action specified {action}"
        raise ValueError(msg)

    @staticmethod
    def proto(proto: str) -> str:
        """Return `proto` when it is tcp, udp, icmp or ip in any case, and raise ValueError otherwise.

        The value is returned as written, not lower-cased."""
        protos = {"tcp", "udp", "icmp", "ip"}

        if proto.lower() in protos:
            return proto
        msg = f"Unsupported Protocol {proto} "
        raise ValueError(msg)

    @staticmethod
    def __ip_to_tuple(ip: str) -> Tuple[bool, str]:
        if ip.startswith("!"):
            ip = ip.lstrip("!")
            return False, ip
        return True, ip

    def __form_ip_list(self, ip_list: str) -> List[Tuple[bool, str]]:
        return [self.__ip_to_tuple(ip) for ip in ip_list.split(",")]

    def __flatten_ip(self, ip):
        list_deny = True
        if ip.startswith("!"):
            list_deny = False
            ip = ip.lstrip("!")
        _ip_list = []
        _not_nest = True
        ip = re.sub(r"^\[|\]$", "", ip)
        ip = re.sub(r'"', "", ip)
        if re.search(r"(\[.*\])", ip):
            _not_nest = False
            nest = re.split(r",(!?\[.*\])", ip)
            nest = filter(None, nest)
            # unnest from _ip_list
            _return_ips = []
            for item in nest:
                if re.match(r"^\[|^!\[", item):
                    nested = self.__flatten_ip(item)
                    _return_ips.append(nested)
                    continue
                _ip_list = self.__form_ip_list(item)
                for _ip in _ip_list:
                    _return_ips.append(_ip)
            return list_deny, _return_ips
        if _not_nest:
            _ip_list = self.__form_ip_list(ip)
            return list_deny, _ip_list
        return None

    def __validate_ip(self, ips):
        variables = {
            "$EXTERNAL_NET",
            "$HTTP_SERVERS",
            "$INTERNAL_NET",
            "$SQL_SERVERS",
            "$SMTP_SERVERS",
            "$DNS_SERVERS",
            "$HOME_NET",
            "HOME_NET",
            "any",
        }

        for item in ips:
            if isinstance(item, bool):
                pass

            if isinstance(item, list):
                for ip in item:
                    self.__validate_ip(ip)

            if isinstance(item, str):
                if item not in variables:
                    if "/" in item:
                        ipaddress.ip_network(item)
                    else:
                        ipaddress.ip_address(item)
        return True

    def ip(self, ip):
        """Parse a source or destination address field.

        Accepts one address or variable, a `!` negation, a comma-separated list, or a
        bracketed list (nested brackets allowed). Returns the tuple (allowed, value),
        where `allowed` is False for a `!` negation. For a list, `value` is a list of
        such tuples, and a nested list gives a nested tuple. Raises ValueError for an
        address or variable that is not valid. Returns None when `ip` is not a string."""
        if isinstance(ip, str):
            ip = ip.strip('"')
            # CTIParsor patch (#519): a single bracketed address or variable
            # (`[$HOME_NET]`, `![192.168.1.1]`) is a list of one, so it takes the
            # list path too.  An unclosed `[` is not bracketed and stays refused.
            if re.search(r",", ip) or re.search(r"^!?\[.*\]$", ip):
                item = self.__flatten_ip(ip)
                ip = item
            else:
                ip = self.__ip_to_tuple(ip)
            valid = self.__validate_ip(ip)
            if valid:
                return ip
            raise ValueError(f"Invalid IP or variable: {ip}")
        return None

    # pylint: disable=too-many-branches
    # pylint: disable=too-many-locals
    # pylint: disable=too-many-statements
    @staticmethod
    def port(port):
        """Parse a source or destination port field.

        Accepts a number, a range `low:high`, an open range `:high` or `low:`, a variable
        such as `$HTTP_PORTS`, `any`, or a bracketed list. Returns (allowed, value):
        `allowed` is False for a `!` negation, and `value` is the port text, or a list of
        (allowed, item) pairs for a bracketed list. Raises ValueError for a malformed port
        or a number outside 0 to 65535."""
        variables = {"any", "$HTTP_PORTS"}

        # is the source marked as not
        if port.startswith("!"):
            if_not = False
            port = port.strip("!")
        else:
            if_not = True
        # is it a list ?
        # if it is, then make it a list from the string
        # Snort allows for ports marked between
        # square brackets and are used to define lists
        # correct:
        # >> [80:443,!90,8080]
        # >> ![80:443]
        # >> [!80:443]
        if port.startswith("["):
            if port.endswith("]"):
                port = port[1:-1].split(",")
            else:
                raise ValueError("Port list is malformed")

        if isinstance(port, list):
            ports = []

            for item in port:
                not_range = True

                if ":" in item:
                    # Checking later on if port is [prt:] or [:prt]
                    open_range = False
                    items = item.split(":", 1)
                    message = ""
                    for prt in items:
                        message = f"Port range is malformed {item}"
                        prt = prt.lstrip("!")
                        if not prt:
                            open_range = True
                            continue

                        try:
                            prt = int(prt)
                        except Exception as e:
                            raise ValueError(message) from e

                        if prt < 0 or prt > 65535:
                            raise ValueError(message)

                    for index, value in enumerate(items):
                        value = value.lstrip("!")
                        items[index] = value

                    if not open_range:
                        try:
                            a = int(items[-1])
                            b = int(items[0])
                        except Exception as e:
                            raise ValueError(message) from e
                        if a - b < 0:
                            raise ValueError(message)
                    not_range = False

                port_not = True
                if re.search("^!", item):
                    port_not = False
                    item = item.strip("!")
                if not_range:
                    # CTIParsor patch (#520): `if item.lower()` was always true, so no
                    # listed port was range-checked.
                    if item.lower() in variables or re.search(r"^\$+", item):
                        ports.append((port_not, item))
                        continue
                    try:
                        prt = int(item)
                        if prt < 0 or prt > 65535:
                            raise ValueError(f"Port is out of range {item}")
                    except ValueError as e:
                        raise ValueError(f"Unknown port {item}") from e
                ports.append((port_not, item))

            return if_not, ports

        if isinstance(port, str):
            # Parsing ports like: :8080, 80:, 80:443
            # and passes all variables ex: $HTTP
            # ranges do not accept denial (!)
            # CTIParsor patch (#520): `if port or` was always true, so the range and
            # single-port checks below never ran.
            if port.lower() in variables or re.search(r"^\$+", port):
                return if_not, port

            if re.search(":", port):
                message = f"Port is out of range {port}"
                ports = port.split(":")
                for portl in ports:
                    portl.lstrip("!")
                    if not portl:
                        continue
                    # CTIParsor patch (#520): `if portl or` was always true.
                    if portl.lower() in variables or re.search(r"^\$+", portl):
                        continue
                    try:
                        portl = int(portl)

                    except ValueError as e:
                        raise ValueError(message) from e
                    if portl < 0 or portl > 65535:
                        raise ValueError(message)

                return if_not, port

            # Parsing a single port
            # single port accepts denial.
            try:
                # CTIParsor patch (#520): was `<= 65535 or < 0`, which took every negative port.
                if 0 <= int(port) <= 65535:
                    return if_not, port

                if int(port) > 65535 or int(port) < 0:
                    raise ValueError

                return None  # TODO: verify this is intended behavior

            except Exception as e:
                msg = f'Unknown port: "{port}" '
                raise ValueError(msg) from e
        else:
            message = f'Unknown port "{port}"'
            raise ValueError(message)

    @staticmethod
    def destination(dst):
        """Return `dst` when it is the arrow `->` or `<>`, and raise ValueError otherwise."""
        destinations = {"->": "to_dst", "<>": "bi_direct"}

        if dst in destinations:
            return dst
        msg = f"Invalid destination variable {dst}"
        raise ValueError(msg)

    def get_header(self):
        """Return the header: the text before the first `(` of the rule.

        Raises SyntaxError when the rule does not match the header-and-options shape. The
        option block must end with `;)`."""
        if re.match(r"(^[a-z|A-Z].+?)?(\(.+;\)|;\s\))", self.rule.lstrip()):
            header = self.rule.split("(", 1)
            return header[0]
        msg = f"Error in syntax, check if rulehas been closed properly {self.rule} "
        raise SyntaxError(msg)

    @staticmethod
    def remove_leading_spaces(string: str) -> str:
        """Return `string` with its leading and trailing whitespace removed (`str.strip`)."""
        return string.strip()

    def get_options(self):
        """Return the options as a list of strings, in rule order.

        The option block is the text between the first `(` and the closing `)`. It is
        split at each `;` that is not preceded by a backslash. Raises ValueError when the
        block does not end with `)`."""
        options = f"{self.rule.split('(', 1)[-1].lstrip().rstrip()}"
        if not options.endswith(")"):
            raise ValueError(
                "Snort rule options is not closed properly, " "you have a syntax error"
            )

        op_list = []

        value = ""
        option = ""
        last_char = ""

        for char in options.rstrip(")"):
            if char != ";":
                value = value + char
                option = option + char

            if char == ";" and last_char != "\\":
                op_list.append(option.strip())
                value = option = ""

            last_char = char

        return op_list

    def parse_header(self):  # pylint: disable=too-many-statements
        """Parse the rule header into an ordered dict keyed by field name.

        The header has seven fields (action, protocol, source, source port, arrow,
        destination, destination port), or one field, which gives the action alone. The
        fields are matched in that order. Raises ValueError when the header is missing or
        has another number of fields."""
        # OrderedDict(
        #     [
        #         ("action", "alert"),
        #         ("proto", "tcp"),
        #         ("source", (True, "$HOME_NET")),
        #         ("src_port", (True, "any")),
        #         ("arrow", "->"),
        #         ("destination", (False, "$EXTERNAL_NET")),
        #         ("dst_port", (True, "any")),
        #     ]
        # )

        if self.get_header():
            header = self.get_header()
            if re.search(r"[,\[\]]\s", header):
                header = re.sub(r",\s+", ",", header)
                header = re.sub(r"\s+,", ",", header)
                header = re.sub(r"\[\s+", "[", header)
                header = re.sub(r"\s+\]", "]", header)
            header = header.split()
        else:
            raise ValueError("Header is missing, or unparsable")
        # get rid of empty list elements
        header = list(filter(None, header))
        header_dict = collections.OrderedDict()
        size = len(header)
        if not size == 7 and not size == 1:
            msg = f"Snort rule header is malformed {header}"
            raise ValueError(msg)

        for item in header:
            if "action" not in header_dict:
                action = self.actions(item)
                header_dict["action"] = action
                continue

            if "proto" not in header_dict:
                try:
                    proto = self.proto(item)
                    header_dict["proto"] = proto
                    continue
                except Exception as perror:
                    raise ValueError(perror) from perror

            if "source" not in header_dict:
                try:
                    src_ip = self.ip(item)
                    header_dict["source"] = src_ip
                    continue
                except Exception as serror:
                    raise ValueError(serror) from serror

            if "src_port" not in header_dict:
                src_port = self.port(item)
                header_dict["src_port"] = src_port
                continue

            if "arrow" not in header_dict:
                dst = self.destination(item)
                header_dict["arrow"] = dst
                continue

            if "destination" not in header_dict:
                dst_ip = self.ip(item)
                header_dict["destination"] = dst_ip
                continue

            if "dst_port" not in header_dict:
                dst_port = self.port(item)
                header_dict["dst_port"] = dst_port
                continue

        return header_dict

    def parse_options(self, rule=None):
        """Parse the option block into an ordered dict keyed by position.

        Each value is (name, values). The text after the first `:` is split at commas,
        except for pcre, whose text is kept as one string. An option without `:` has the
        empty string as its values. A `rule` argument replaces self.rule before parsing."""
        if rule:
            self.rule = rule
        opts = self.get_options()

        options_dict = collections.OrderedDict()
        for index, option_string in enumerate(opts):
            if ":" in option_string:
                option = option_string.split(":", 1)
                key, value = option
                if key != "pcre":
                    value = value.split(",")
                options_dict[index] = (key, value)
            else:
                options_dict[index] = (option_string, "")
        return options_dict

    def validate_options(self, options):
        """Check that each option name is known to Dicts, and return the options unchanged.

        Raises ValueError with "unrecognized option" for a name that no keyword table
        holds. A single-value content modifier is accepted without further checks."""
        for _index, option in options.items():
            key, value = option
            # CTIParsor patch (#422): OpenCTI sets `opt` only on some paths
            # (when len(value) == 1), so a bare option such as `http.uri;` kept
            # the True of the option before it, or raised UnboundLocalError when
            # it came first.  `opt` is now reset for every option, so an option
            # Dicts does not know is rejected as unrecognized, with or without
            # an argument.  Nothing else changes.
            opt = False
            if len(value) == 1:
                content_mod = self.dicts.content_modifiers(value[0])
                if content_mod:
                    # TODO: implement this feature
                    continue
            gen_option = self.dicts.options(key)
            if gen_option:
                opt = True
                continue
            pay_option = self.dicts.options(key)
            if pay_option:
                opt = True
                continue
            non_pay_option = self.dicts.options(key)
            if non_pay_option:
                opt = True
                continue
            post_detect = self.dicts.options(key)
            if post_detect:
                opt = True
                continue
            threshold = self.dicts.options(key)
            if threshold:
                opt = True
                continue
            if not opt:
                message = f"unrecognized option: {key}"
                raise ValueError(message)
        return options


class Sanitizer:
    """Normalises option values before the rule is written back.

    Only pcre is normalised. See `pcre`."""
    def __init__(self):
        self.methods = {
            "pcre": self.pcre,
        }

    def sanitize(self, parsed):
        """Normalise the option values of a parsed rule in place, and return the rule.

        An option whose name has a method in self.methods is replaced by the result of
        that method. The other options are left as they are."""
        options = parsed["options"]
        # CTIParsor patch (#521): options maps index -> (name, value) and methods is
        # keyed by name, so match the name and keep the tuple shape.
        for idx, (opt_name, opt_val) in options.items():
            if opt_name in self.methods:
                options[idx] = (opt_name, self.methods[opt_name](opt_val))

        parsed["options"] = options
        return parsed

    @staticmethod
    def pcre(value: Union[str, List]) -> Union[str, List]:
        """Return a pcre value in the form "/regex/flags", adding the quotes and slashes that are missing.

        A value that already ends in a slash, with optional flags after it, gets no second
        slash. A list keeps its shape, and only its first element is normalised. An empty
        value is returned as it is."""
        # The parser stores a pcre option as a str, but list input keeps its shape (#624).
        if isinstance(value, list):
            if not value:
                return value
            return [Sanitizer.pcre(value[0]), *value[1:]]
        if not value:
            return value
        body = value[1:] if value.startswith('"') else value
        body = body[:-1] if body.endswith('"') else body
        if not body.startswith("/"):
            body = f"/{body}"
        # Only add the closing slash when the regex does not already end with /flags (#624).
        if not re.fullmatch(r"/.*/[ismxAEGRUBPHMCOIDKYS]*", body, re.DOTALL):
            body = f"{body}/"
        return f'"{body}"'

    @staticmethod
    def depth(options):
        """Return the larger of the rule's depth value and dsize value.

        The first depth option and the first dsize option are used. The dsize operator,
        which is the first non-digit character, is stripped from both ends of the value
        before the comparison. A rule without either option raises IndexError."""
        depth_idx = [idx for idx in options if "depth" in options[idx]][0]
        dsize_idx = [idx for idx in options if "dsize" in options[idx]][0]
        # CTIParsor patch (#521): each option is a (name, values) tuple, so the value is [1].
        depth = options[depth_idx][1][0]
        dsize = options[dsize_idx][1][0]
        full_dsize = re.split(r"[0-9]+", dsize)
        operand = [x for x in full_dsize if x]
        # CTIParsor patch (#521): a plain dsize (`20`) has no operator to strip.
        if operand:
            dsize = dsize.strip(operand[0])
        if int(depth) < int(dsize):
            return dsize
        return depth


class SerializeRule:
    """Writes a parsed rule back to Snort text: header, options, or the whole rule."""
    def __init__(self, rule):
        self.rule = rule

    def __getitem__(self, key):
        if "rule" in key:
            return self.serialize_rule()
        if "header" in key:
            return self.serialize_header()
        if "options" in key:
            return self.serialize_options()
        return None

    def __str__(self):
        return self.serialize_rule()

    def __list_serializer(self, list_bool: bool, items: List) -> str:
        serialised = str()
        for _bool, item in items:
            if isinstance(item, list):
                serialised = f"{serialised},{self.__list_serializer(_bool, item)}"
            else:
                if _bool:
                    serialised = f"{serialised},{item}"
                if not _bool:
                    serialised = f"{serialised},!{item}"

        serialised_list = serialised.lstrip(",")

        if list_bool:
            serialised = f"[{serialised_list}]"
        else:
            serialised = f"![{serialised_list}]"

        return serialised

    def serialize_header_item(self, item: Any) -> Optional[str]:
        """Return the text of one header field.

        A string is returned as it is. For a (allowed, value) tuple, a list value is written
        as a bracketed list, with a leading `!` when it is not allowed. A single value in a
        tuple is returned without its `!`. Any other type gives None."""
        if isinstance(item, str):
            return item

        if isinstance(item, tuple):
            _bool, item = item
            if isinstance(item, list):
                return self.__list_serializer(_bool, item)
            return item
        return None  # TODO: verify this is intended behavior

    def serialize_header(self, header: Dict = None) -> str:
        """Return the header fields, each preceded by a space.

        The fields come from `header`, or from self.rule["header"] when `header` is empty."""
        serialised = str()
        if not header:
            header = self.rule["header"]
        assert header is not None
        for _key, value in header.items():
            item = self.serialize_header_item(value)
            serialised = f"{serialised} {item}"
        return serialised

    def serialize_options(self, options: Dict = None) -> str:
        """Return the option block as "(name:value; ...)".

        The options come from `options`, or from self.rule["options"] when `options` is
        empty. An option without a value is written as its name alone. A pcre value is
        written as it is, and other values are joined with commas."""
        options_list = []
        if not options:
            options = self.rule["options"]
        assert options is not None
        for _index, option in options.items():
            key, value = option
            if value:
                # A pcre value is a plain str: joining it would put a comma between characters (#624).
                if isinstance(value, str):
                    option_value = f"{key}:{value}"
                else:
                    option_value = f"{key}:{','.join(value)}"
            else:
                option_value = f"{key}"
            options_list.append(option_value)

        _options = "; ".join(str(e) for e in options_list)
        serialized_options = f"({_options})"
        return serialized_options

    def serialize_rule(self):
        """Return the whole rule: the header, a space, then the option block."""
        return f"{self.serialize_header()} {self.serialize_options()}".lstrip()
