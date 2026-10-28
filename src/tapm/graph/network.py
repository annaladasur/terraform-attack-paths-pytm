"""Network relationships: security-group rules, internet exposure, load-balancer routing.

Evaluated from the plan: security group inline rules and standalone rule resources,
load balancer scheme and listeners, target-group registrations, public IPs and
public subnets. Evaluated *conservatively*: an edge is only emitted when the plan
shows the traffic is permitted; when a required value is unknown the edge carries
an assumption instead of being silently dropped or silently asserted.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from ..evidence.ledger import Ledger
from ..terraform.plan import Plan, PlanResource
from ..terraform.source import SourceIndex
from ..util import as_list
from .model import INTERNET, Edge, Graph

OPEN_V4 = "0.0.0.0/0"
OPEN_V6 = "::/0"
INTERNAL = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
                                              "127.0.0.0/8", "169.254.0.0/16", "fc00::/7", "fe80::/10", "::1/128")]


def is_public_cidr(cidr: str) -> bool:
    """Any range outside private/internal space is reachable from (part of) the internet."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
    return not any(net.version == i.version and net.subnet_of(i) for i in INTERNAL)


@dataclass
class Rule:
    sg: str
    direction: str
    protocol: str
    from_port: int
    to_port: int
    cidrs: list[str] = field(default_factory=list)
    source_sgs: list[str] = field(default_factory=list)
    self_ref: bool = False
    holder: str = ""
    loc: dict | None = None
    handle: str = ""
    ambiguous: bool = False

    def covers(self, port: int | None) -> bool:
        if self.protocol in ("-1", "all"):
            return True
        if self.protocol not in ("tcp", "6"):
            return False
        if port is None:
            return True
        return self.from_port <= port <= self.to_port

    @property
    def internet(self) -> bool:
        return OPEN_V4 in self.cidrs or OPEN_V6 in self.cidrs

    @property
    def public_restricted(self) -> list[str]:
        """Specific public ranges (e.g. an office IP): internet-reachable, but only from those sources."""
        return [c for c in self.cidrs if c not in (OPEN_V4, OPEN_V6) and is_public_cidr(c)]

    def describe(self) -> str:
        if self.protocol in ("-1", "all"):
            ports = "all traffic"
        elif self.from_port == self.to_port:
            ports = f"{self.protocol}/{self.from_port}"
        else:
            ports = f"{self.protocol}/{self.from_port}-{self.to_port}"
        srcs = self.cidrs + [f"sg:{s}" for s in self.source_sgs] + (["self"] if self.self_ref else [])
        word = "from" if self.direction == "ingress" else "to"
        return f"{self.sg} {self.direction} {ports} {word} {', '.join(srcs) or '(none)'}"


class Network:
    def __init__(self, plan: Plan, src: SourceIndex, graph: Graph, ledger: Ledger, tf: dict[str, str]):
        self.plan, self.src, self.g, self.ledger, self.tf = plan, src, graph, ledger, tf
        self.rules: list[Rule] = []
        self.notes: list[dict] = []

    # ------------------------------------------------------------- rules
    def collect_rules(self) -> None:
        for sg in self.plan.by_type("aws_security_group"):
            for direction in ("ingress", "egress"):
                vals = as_list(sg.values.get(direction))
                unk = sg.unknown.get(direction)
                refs = [r for r in sg.references.get(direction, [])
                        if any(x.type == "aws_security_group" for x in self.plan.instances_of(r))]
                unknown_idx = [i for i, _ in enumerate(vals)
                               if isinstance(unk, list) and i < len(unk) and isinstance(unk[i], dict) and unk[i].get("security_groups")]
                for i, rv in enumerate(vals):
                    srcs = list(rv.get("security_groups") or [])
                    ambiguous = False
                    if i in unknown_idx:
                        srcs = [a.address for ref in refs for a in self.plan.instances_of(ref)]
                        ambiguous = len(unknown_idx) > 1
                    # known security group ids that name a planned SG by id are not resolvable; keep as-is
                    self._add(Rule(sg.address, direction, str(rv.get("protocol", "")), int(rv.get("from_port") or 0),
                                   int(rv.get("to_port") or 0), sorted(set((rv.get("cidr_blocks") or []) + (rv.get("ipv6_cidr_blocks") or []))),
                                   sorted(set(srcs)), bool(rv.get("self")), sg.address, ambiguous=ambiguous),
                              needle=(rv.get("cidr_blocks") or [None])[0] or rv.get("description"), member=direction)
        for r in self.plan.by_type("aws_security_group_rule"):
            sgs = [a.address for ref in r.references.get("security_group_id", []) for a in self.plan.instances_of(ref)]
            srcs = [a.address for ref in r.references.get("source_security_group_id", []) for a in self.plan.instances_of(ref)]
            for sg in sgs:
                self._add(Rule(sg, str(r.values.get("type")), str(r.values.get("protocol", "")), int(r.values.get("from_port") or 0),
                               int(r.values.get("to_port") or 0), sorted(set((r.values.get("cidr_blocks") or []) + (r.values.get("ipv6_cidr_blocks") or []))),
                               sorted(srcs), bool(r.values.get("self")), r.address))
        for t, direction in (("aws_vpc_security_group_ingress_rule", "ingress"), ("aws_vpc_security_group_egress_rule", "egress")):
            for r in self.plan.by_type(t):
                sgs = [a.address for ref in r.references.get("security_group_id", []) for a in self.plan.instances_of(ref)]
                srcs = [a.address for ref in r.references.get("referenced_security_group_id", []) for a in self.plan.instances_of(ref)]
                cidrs = [c for c in (r.values.get("cidr_ipv4"), r.values.get("cidr_ipv6")) if c]
                proto = str(r.values.get("ip_protocol", ""))
                for sg in sgs:
                    self._add(Rule(sg, direction, proto, int(r.values.get("from_port") or 0), int(r.values.get("to_port") or 0),
                                   sorted(cidrs), sorted(srcs), False, r.address))

    def _add(self, rule: Rule, needle: str | None = None, member: str | None = None) -> None:
        holder = self.plan.resources[rule.holder]
        loc = None
        if member:
            loc = self.src.locate_member(holder.base, member, needle)
        rule.loc = loc or self.src.locate(holder.base)
        rule.handle = self.ledger.add(
            "NET", ("sg_rule", rule.sg, rule.direction, rule.protocol, rule.from_port, rule.to_port, rule.cidrs, rule.source_sgs, rule.self_ref),
            rule.describe(), source=rule.loc,
            data={"security_group": rule.sg, "direction": rule.direction, "protocol": rule.protocol,
                  "from_port": rule.from_port, "to_port": rule.to_port, "cidrs": rule.cidrs,
                  "source_security_groups": rule.source_sgs, "internet": rule.internet,
                  "public_cidrs": rule.public_restricted, "ambiguous": rule.ambiguous},
            refs=[self.tf[rule.holder]] + ([self.tf[rule.sg]] if rule.sg in self.tf else []),
        )
        self.rules.append(rule)

    def ingress(self, sg: str) -> list[Rule]:
        return [r for r in self.rules if r.sg == sg and r.direction == "ingress"]

    def sgs_of(self, r: PlanResource) -> list[str]:
        attrs = {"aws_instance": ("vpc_security_group_ids", "security_groups"), "aws_lb": ("security_groups",),
                 "aws_alb": ("security_groups",), "aws_db_instance": ("vpc_security_group_ids",),
                 "aws_lambda_function": ("vpc_config",), "aws_ecs_service": ("network_configuration",),
                 "aws_launch_template": ("vpc_security_group_ids", "network_interfaces")}.get(r.type, ())
        out = []
        for a in attrs:
            out += [x.address for ref in r.references.get(a, []) for x in self.plan.instances_of(ref) if x.type == "aws_security_group"]
        if r.type == "aws_ecs_service" and not out:  # bridge/host networking: the container instances' groups apply
            from .ecs import cluster_of, hosts

            for h in hosts(self.plan, cluster_of(self.plan, r)):
                out += self.sgs_of(h)
        return sorted(set(out))

    # ---------------------------------------------------------- structure
    def structural_edges(self) -> None:
        for r in self.plan.resources.values():
            if r.address not in self.g.nodes or r.mode != "managed":
                continue
            for sg in self.sgs_of(r):
                self.g.add_edge(Edge("ATTACHES", r.address, sg, label="security_group",
                                     evidence=[self.tf[r.address], self.tf[sg]]))
            for attr in ("vpc_id",):
                for ref in r.references.get(attr, []):
                    for v in self.plan.instances_of(ref):
                        if v.type == "aws_vpc" and r.type == "aws_subnet":
                            self.g.add_edge(Edge("CONTAINS", v.address, r.address, evidence=[self.tf[v.address], self.tf[r.address]]))
            for attr in ("subnet_id", "subnets", "subnet_ids"):
                for ref in r.references.get(attr, []):
                    for s in self.plan.instances_of(ref):
                        if s.type == "aws_subnet":
                            self.g.add_edge(Edge("CONTAINS", s.address, r.address, evidence=[self.tf[s.address], self.tf[r.address]]))

    # ------------------------------------------------------------ exposure
    def public_subnet(self, subnet: PlanResource) -> bool | None:
        """True if a route table associated with the subnet routes 0.0.0.0/0 to an internet gateway."""
        for assoc in self.plan.by_type("aws_route_table_association"):
            if subnet.base not in assoc.references.get("subnet_id", []):
                continue
            for rref in assoc.references.get("route_table_id", []):
                for rt in self.plan.instances_of(rref):
                    if any(x.type == "aws_internet_gateway" for ref in rt.references.get("route", [])
                           for x in self.plan.instances_of(ref)):
                        return True
                    for route in as_list(rt.values.get("route")):
                        if route.get("cidr_block") == OPEN_V4 and str(route.get("gateway_id", "")).startswith("igw-"):
                            return True
            return False
        return None

    def internet_rules(self, sgs: list[str], port: int | None) -> list[Rule]:
        """Rules admitting 0.0.0.0/0; if there are none, rules admitting specific public ranges."""
        open_ = [r for sg in sgs for r in self.ingress(sg) if r.internet and r.covers(port)]
        if open_:
            return open_
        return [r for sg in sgs for r in self.ingress(sg) if r.public_restricted and r.covers(port)]

    @staticmethod
    def _source_precondition(rules: list[Rule]) -> str | None:
        return None if any(r.internet for r in rules) else "source_ip_allowed"

    def expose(self) -> None:
        self.g.nodes.get(INTERNET)
        # load balancers
        for lb in self.plan.by_type("aws_lb", "aws_alb"):
            if lb.address not in self.g.nodes:
                continue
            internal = lb.values.get("internal")
            listeners = [ls for ls in self.plan.by_type("aws_lb_listener") if lb.base in ls.references.get("load_balancer_arn", [])]
            if internal is not False:
                if internal is None:
                    self.notes.append({"resource": lb.address, "note": "load balancer scheme unknown at plan time"})
                continue
            lb_net = self.ledger.add("NET", ("lb_scheme", lb.address), f"{lb.address} is internet-facing (internal = false)",
                                     source=self.src.locate_member(lb.base, "internal") or self.src.locate(lb.base),
                                     refs=[self.tf[lb.address]])
            sgs = self.sgs_of(lb)
            for ls in listeners:
                port = ls.values.get("port")
                ev = [self.tf[lb.address], self.tf[ls.address], lb_net]
                if sgs:
                    rules = self.internet_rules(sgs, port)
                    if not rules:
                        self.notes.append({"resource": lb.address, "note": f"internet-facing but no security group rule admits 0.0.0.0/0 on {port}"})
                        self.g.nodes[lb.address].flags["internet_blocked_by_sg"] = True
                        continue
                    ev += [r.handle for r in rules]
                else:
                    self.g.nodes[lb.address].flags["no_security_group"] = True
                self.g.add_edge(Edge("EXPOSES", INTERNET, lb.address, label=f"{ls.values.get('protocol') or 'tcp'}/{port}",
                                     data={"ports": [port], "protocol": ls.values.get("protocol")}, evidence=ev,
                                     precondition=self._source_precondition(rules) if sgs else None))
        # instances with public addresses
        for inst in self.plan.by_type("aws_instance"):
            if inst.address not in self.g.nodes:
                continue
            public_ip = inst.values.get("associate_public_ip_address")
            subnet = next((s for ref in inst.references.get("subnet_id", []) for s in self.plan.instances_of(ref)), None)
            reasons = []
            if public_ip is True:
                reasons.append("associate_public_ip_address = true")
            elif public_ip is None and subnet is not None and subnet.values.get("map_public_ip_on_launch") is True:
                reasons.append(f"{subnet.address} maps public IPs on launch")
            if not reasons:
                continue
            routed = self.public_subnet(subnet) if subnet is not None else None
            if routed is False:
                self.notes.append({"resource": inst.address, "note": "public IP requested but subnet has no internet route"})
                continue
            rules = self.internet_rules(self.sgs_of(inst), None)
            if not rules:
                continue
            ports = sorted({f"{r.protocol}/{r.from_port}" if r.from_port == r.to_port else f"{r.protocol}/{r.from_port}-{r.to_port}" for r in rules})
            h = self.ledger.add("NET", ("public_ip", inst.address), f"{inst.address} has a public address ({'; '.join(reasons)})",
                                source=self.src.locate_member(inst.base, "associate_public_ip_address") or self.src.locate(inst.base),
                                refs=[self.tf[inst.address]] + ([self.tf[subnet.address]] if subnet is not None else []))
            self.g.add_edge(Edge("EXPOSES", INTERNET, inst.address, label=",".join(ports), data={"ports": ports},
                                 evidence=[self.tf[inst.address], h] + [r.handle for r in rules],
                                 conditional=routed is None, precondition=self._source_precondition(rules)))
        # databases
        for db in self.plan.by_type("aws_db_instance"):
            if db.values.get("publicly_accessible") is not True or db.address not in self.g.nodes:
                continue
            port = db.values.get("port")
            rules = self.internet_rules(self.sgs_of(db), port)
            if not rules:
                continue
            h = self.ledger.add("NET", ("public_db", db.address), f"{db.address} publicly_accessible = true",
                                source=self.src.locate_member(db.base, "publicly_accessible") or self.src.locate(db.base),
                                refs=[self.tf[db.address]])
            self.g.add_edge(Edge("EXPOSES", INTERNET, db.address, label=f"tcp/{port}", data={"ports": [port]},
                                 evidence=[self.tf[db.address], h] + [r.handle for r in rules],
                                 precondition=self._source_precondition(rules)))
        # lambda function URLs without auth
        for url in self.plan.by_type("aws_lambda_function_url"):
            if url.values.get("authorization_type") != "NONE":
                continue
            for ref in url.references.get("function_name", []):
                for fn in self.plan.instances_of(ref):
                    h = self.ledger.add("NET", ("function_url", url.address), f"{url.address} authorization_type = NONE",
                                        source=self.src.locate(url.base), refs=[self.tf[url.address]])
                    self.g.add_edge(Edge("EXPOSES", INTERNET, fn.address, label="https/function_url",
                                         evidence=[self.tf[fn.address], self.tf[url.address], h]))

    # ---------------------------------------------------------- API gateways
    def _api_backend(self, refs: list[str]) -> list[PlanResource]:
        return [t for ref in refs for t in self.plan.instances_of(ref)
                if t.type in ("aws_lambda_function", "aws_instance", "aws_lb", "aws_alb") and t.address in self.g.nodes]

    def _lambda_invokable(self, fn: PlanResource) -> list[str]:
        """aws_lambda_permission records letting API Gateway invoke ``fn``; none means the call would be refused."""
        return [self.tf[p.address] for p in self.plan.by_type("aws_lambda_permission")
                if p.values.get("principal") == "apigateway.amazonaws.com"
                and any(fn.address == x.address for ref in p.references.get("function_name", []) for x in self.plan.instances_of(ref))]

    def api_gateways(self) -> None:
        """REST (v1) and HTTP/WebSocket (v2) APIs: public unless PRIVATE; a route without authorization reaches its backend."""
        for api in self.plan.by_type("aws_api_gateway_rest_api", "aws_apigatewayv2_api"):
            if api.address not in self.g.nodes:
                continue
            types = [t for ec in as_list(api.values.get("endpoint_configuration")) for t in (ec or {}).get("types") or []]
            if "PRIVATE" in types:
                continue
            v2 = api.type == "aws_apigatewayv2_api"
            routes = []  # (method-or-route resource, integration, backends)
            if not v2:
                for integ in self.plan.by_type("aws_api_gateway_integration"):
                    if api.base not in integ.references.get("rest_api_id", []):
                        continue
                    meths = [m for ref in integ.references.get("http_method", []) for m in self.plan.instances_of(ref)
                             if m.type == "aws_api_gateway_method"]
                    for m in meths:
                        if m.values.get("authorization") == "NONE":
                            routes.append((m, integ, self._api_backend(integ.references.get("uri", []))))
            else:
                for rt in self.plan.by_type("aws_apigatewayv2_route"):
                    if api.base not in rt.references.get("api_id", []) or rt.values.get("authorization_type") not in ("NONE", None):
                        continue
                    for ref in rt.references.get("target", []):
                        for integ in self.plan.instances_of(ref):
                            if integ.type == "aws_apigatewayv2_integration":
                                routes.append((rt, integ, self._api_backend(integ.references.get("integration_uri", []))))
            if not routes:
                self.notes.append({"resource": api.address, "note": "no unauthenticated route found; not treated as an entry"})
                continue
            first = routes[0][0]
            h = self.ledger.add("NET", ("api_open", api.address),
                                f"{api.address} is a public API; {first.address} has no authorization"
                                + (f" (and {len(routes) - 1} more route(s))" if len(routes) > 1 else ""),
                                source=self.src.locate_member(first.base, "authorization") or self.src.locate(first.base),
                                refs=[self.tf[api.address]] + [self.tf[m.address] for m, _, _ in routes[:20]])
            self.g.add_edge(Edge("EXPOSES", INTERNET, api.address, label="https/api_gateway", data={"ports": [443], "protocol": "HTTPS"},
                                 evidence=[self.tf[api.address], h]))
            seen = set()
            for m, integ, backends in routes:
                for b in backends:
                    if b.address in seen:
                        continue
                    seen.add(b.address)
                    ev = [self.tf[api.address], self.tf[m.address], self.tf[integ.address], self.tf[b.address], h]
                    perm = self._lambda_invokable(b) if b.type == "aws_lambda_function" else []
                    self.g.add_edge(Edge("ROUTES_TO", api.address, b.address, label=f"https/{integ.values.get('type') or integ.values.get('integration_type') or 'integration'}",
                                         data={"integration": integ.address, "route": m.address, "port": 443}, evidence=ev + perm,
                                         conditional=b.type == "aws_lambda_function" and not perm))

    # --------------------------------------------------------------- routing
    def route(self) -> None:
        for lb in self.plan.by_type("aws_lb", "aws_alb"):
            if lb.address not in self.g.nodes:
                continue
            lb_sgs = self.sgs_of(lb)
            lb_subnets = [s for ref in lb.references.get("subnets", []) for s in self.plan.instances_of(ref)]
            for ls in self.plan.by_type("aws_lb_listener"):
                if lb.base not in ls.references.get("load_balancer_arn", []):
                    continue
                for tref in ls.references.get("default_action", []):
                    for tg in self.plan.instances_of(tref):
                        if tg.type != "aws_lb_target_group":
                            continue
                        port = tg.values.get("port")
                        for att in self.plan.by_type("aws_lb_target_group_attachment"):
                            if tg.base not in att.references.get("target_group_arn", []):
                                continue
                            for target_ref in att.references.get("target_id", []):
                                for target in self.plan.instances_of(target_ref):
                                    self._route(lb, ls, tg, att, target, port, lb_sgs, lb_subnets)
                        for svc in self.plan.by_type("aws_ecs_service"):  # ECS registers the tasks itself
                            if svc.address in self.g.nodes and tg.base in svc.references.get("load_balancer", []):
                                self._route(lb, ls, tg, svc, svc, port, lb_sgs, lb_subnets)

    def _route(self, lb, ls, tg, att, target, port, lb_sgs, lb_subnets) -> None:
        if target.address not in self.g.nodes:
            return
        ev = sorted({self.tf[x.address] for x in (lb, ls, tg, att, target)})
        tsgs = self.sgs_of(target)
        conditional = False
        if target.type in ("aws_instance", "aws_ecs_service"):
            allowing = []
            for r in (rr for sg in tsgs for rr in self.ingress(sg)):
                if not r.covers(port):
                    continue
                if any(s in lb_sgs for s in r.source_sgs) or r.internet or _cidr_covers(r.cidrs, lb_subnets):
                    allowing.append(r)
            if tsgs and not allowing:
                self.notes.append({"resource": target.address, "note": f"registered with {tg.address} but its security groups do not admit {lb.address} on {port}"})
                return
            if not tsgs:
                conditional = True
            ev += [r.handle for r in allowing]
        self.g.add_edge(Edge("ROUTES_TO", lb.address, target.address, label=f"{tg.values.get('protocol') or 'tcp'}/{port}",
                             data={"target_group": tg.address, "listener": ls.address, "port": port},
                             evidence=ev, conditional=conditional))

    def run(self) -> None:
        self.collect_rules()
        self.structural_edges()
        self.expose()
        self.api_gateways()
        self.route()


def _cidr_covers(cidrs: list[str], subnets: list[PlanResource]) -> bool:
    nets = []
    for c in cidrs:
        try:
            nets.append(ipaddress.ip_network(c, strict=False))
        except ValueError:
            continue
    for s in subnets:
        try:
            sn = ipaddress.ip_network(str(s.values.get("cidr_block")), strict=False)
        except ValueError:
            continue
        if any(sn.version == n.version and sn.subnet_of(n) for n in nets):
            return True
    return False
