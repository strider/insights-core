import string
from insights.parsr import EOF, EOL, Char, Literal, Many, OneLineComment, Opt, QuotedString, String, WSChar

# https://man7.org/linux/man-pages/man1/pmlogger.1.html#CONFIGURATION_FILE_SYNTAX

#    The syntax for the configuration file is as follows.

#    1.   Words are separated by white space (space, tab or newline).

#    2.   The symbol ``#'' (hash) introduces a comment, and all text
#         up to the next newline is ignored.

WS = Many(WSChar | EOL | OneLineComment("#"))

#    3.   Keywords (shown in bold below) must appear literally (i.e.
#         in lower case).

#    4.   Each specification begins with the optional keyword log,
#         followed by one of the states mandatory on, mandatory off,
#         mandatory maybe, advisory on or advisory off.

Log = WS >> Literal("log") << WS
MandatoryOn = WS >> Literal("mandatory on") << WS
MandatoryOff = WS >> Literal("mandatory off") << WS
MandatoryMaybe = WS >> Literal("mandatory maybe") << WS
AdvisoryOn = WS >> Literal("advisory on") << WS
AdvisoryOff = WS >> Literal("advisory off") << WS

#    5.   For the on states, a logging interval must follow using the
#         syntax ``once'', or ``default'', or ``every N timeunits'',
#         or simply ``N timeunits'' - N is an unsigned integer, and
#         timeunits is one of the keywords msec, millisecond, sec,
#         second, min, minute, hour or the plural form of one of the
#         above.

Once = WS >> Literal("once") << WS
Default = WS >> Literal("default") << WS
Every = WS >> Literal("every") << WS
UnsignedInt = String(string.digits).map(int)
TimeUnits = WS >> String(string.ascii_letters) << WS
Freq = Opt(Every) >> (UnsignedInt + TimeUnits)

Interval = Once | Default | Freq
OnStates = MandatoryOn | AdvisoryOn
OtherStates = MandatoryMaybe | MandatoryOff | AdvisoryOff

Preamble = Opt(Log) >> ((OnStates + Interval) | OtherStates)

#    6.   Following the state and possible interval specifications
#         comes a ``{'', followed by a list of one or more metric
#         specifications and a closing ``}''.  The list is white space
#         (or comma) separated.  If there is only one metric
#         specification in the list, the braces are optional.

LeftBrace = WS >> Char("{") << WS
RightBrace = WS >> Char("}") << WS
Comma = WS >> Char(",") << WS

#    7.   A metric specification consists of a metric name optionally
#         followed by a set of instance names.  The metric name
#         follows the standard PCP naming conventions, see PMNS(5),
#         and if the metric name is a non-leaf node in the PMNS (see
#         PMNS(5)), then pmlogger will recursively descend the PMNS
#         and apply the logging specification to all descendent metric
#         names that are leaf nodes in the PMNS.  The set of instance
#         names is a ``['', followed by a list of one or more space
#         (or comma) separated names, numbers or strings, and a
#         closing ``]''.  Elements in the list that are numbers are
#         assumed to be internal instance identifiers, other elements
#         are assumed to be external instance identifiers - see
#         pmGetInDom(3) for more information.

Name = WS >> String(string.ascii_letters + string.digits + "-._") << WS

LeftBracket = WS >> Char('[') << WS
RightBracket = WS >> Char(']') << WS
InstanceName = QuotedString | UnsignedInt | Name
InstanceNames = LeftBracket >> InstanceName.sep_by(Comma | WS) << RightBracket
MetricSpec = Name + Opt(InstanceNames, default=[])

OneMetricSpec = MetricSpec.map(lambda s: [s])
MultipleMetricSpecs = LeftBrace >> MetricSpec.sep_by(Comma | WS) << RightBrace
MetricSpecs = (OneMetricSpec | MultipleMetricSpecs).map(dict)

LogSpec = Preamble + MetricSpecs

LogSpecs = Many(LogSpec)

parse = LogSpecs << EOF
# AccessHeader = WS >> Literal("[access]") << WS
# Rule = WS >> ... << WS
# AccessRules = Many(Rule)
# AccessControl = AccessHeader >> AccessRules
# Doc = LogSpecs + Opt(AccessControl)
# parse = Doc << EOF

#         If no instances are given, then the logging specification is
#         applied to all instances of the associated metric.

#    8.   There may be an arbitrary number of logging specifications.

#    9.   As of PCP version 4.0 and later, any metric name
#         specification that does not resolve to a leaf node in the
#         PMNS is added to an internal list of possible dynamic
#         subtree roots.  PMDAs can dynamically create new metrics
#         below a dynamic root node in their PMNS, and send a
#         notification to clients that the PMNS has changed, see
#         pmdaExtSetFlags(3) and in particular the METRIC CHANGES
#         section for API details.  This mechanism is currently
#         supported by pmdaopenmetrics(1) and pmdammv(1).  When a
#         fetch issued by pmlogger returns with the
#         PMDA_EXT_NAMES_CHANGE flag set, pmlogger will traverse the
#         internal list of possible dynamic subtree nodes and
#         dynamically discover any new metrics.  In effect, as of PCP
#         version 4.0 and later, pmlogger can be configured to
#         dynamically log new metrics that appear in the future, after
#         the configuration file is initially parsed.

#    10.  Following all of the logging specifications, there may be an
#         optional access control section, introduced by the literal
#         token [access].  Thereafter come access control rules that
#         allow or disallow operations from particular hosts or groups
#         of hosts.

#         The operations may be used to interrogate or control a
#         running pmlogger using pmlc(1) and fall into the following
#         classes:

#         enquire
#                interrogate the status of pmlogger and the metrics it
#                is logging
#         advisory
#                Change advisory logging.
#         mandatory
#                Change mandatory logging.
#         all    All of the above.

#         Access control rules are of the form ``allow hostlist :
#         operationlist ;'' and ``disallow hostlist : operationlist
#         ;''.

#         The hostlist follows the syntax and semantics for the access
#         control mechanisms used by PMCD and are fully documented in
#         pmcd(1).  An operationslist is a comma separated list of the
#         operations advisory, mandatory, enquire and all.

#         A missing [access] section allows all access and is
#         equivalent to allow * : all;.

#    The configuration (either from standard input or conffile) is
#    initially scanned by pmcpp(1) with the options -rs and -I
#    $PCP_VAR_DIR/config/pmlogger.  This extends the configuration
#    file syntax with include file processing (%include), a common
#    location to search for include files
#    ($PCP_VAR_DIR/config/pmlogger), macro definitions (%define),
#    macro expansion (%name and %{name}) and conditional inclusion of
#    lines (%ifdef name ... %else ... %endif and %ifndef name ...
#    %else ... %endif).
