# Discovery boundaries

These diagrams describe the implemented discovery layer. Database inspection/recovery is a separate subsystem; a `Configured` result is not an authorization to mutate it.

```mermaid
flowchart TD
    roots[Explicit local roots] --> guard[Reject UNC and reparse paths]
    guard --> queue[Bounded directory queue]
    queue --> metadata[Shallow metadata and fixed Joomla markers]
    metadata --> version[Bounded XML or PHP version literals]
    metadata --> partial[Progress and incomplete coverage findings]
    version --> sites[Discovered Joomla installations]
    roots --> apache[Static Apache parser]
    apache --> mapping[Declared document roots and aliases]
    mapping --> urls[Credential-free loopback URLs only]
    sites --> urls
    urls --> untested[Reachability and runtime remain untested]
```

```mermaid
flowchart TD
    selected[Selected configuration path] --> scope{Within approved roots or exact approved file?}
    scope -->|No| approval[NeedsApproval and pending path only]
    scope -->|Yes| file[Bounded read without PHP execution]
    file --> lexer[Comment-aware tokens and restricted grammar]
    lexer --> literal[Literal properties or explicitly named getenv]
    lexer --> loader[Anchored static include expression]
    loader --> scope
    lexer -->|Dynamic or ambiguous| unresolved[Unsupported or unresolved]
    literal --> validate[One JConfig and required fields validated]
    validate -->|Complete| memory[Private in-memory connection settings]
    validate -->|Incomplete| unresolved
    memory --> result[Configured; authentication not tested]
    result --> evidence[Secret-free status and source paths]
```

```mermaid
flowchart LR
    selection[Selected local roots] --> configs[Bounded Apache config/include catalog]
    configs --> declared[Ports, virtual hosts, aliases, local phpMyAdmin mappings]
    os[Local Windows metadata] --> services[Registry and service-status query only]
    os --> listeners[TCP listening port metadata]
    selection --> tool[Known PHP and Apache executable candidates]
    tool --> child[PHP -n -v or Apache -v]
    child --> timeout[4-second timeout and bounded capture]
    timeout --> token[Recognized version token only]
    declared --> snapshot[SystemSnapshot observations]
    services --> snapshot
    listeners --> snapshot
    token --> snapshot
    snapshot --> limits[No service changes, HTTP requests or runtime claims]
```

Filesystem/registry deadlines are cooperative. Static Apache parsing does not evaluate module/conditional activation. Dynamic PHP is deliberately unsupported. Version commands are explicit diagnostic child processes with timeouts; the discovery scanner itself never executes project code.
