#!/usr/bin/env python3
"""Generate spec/circuit-zk-consent-vectors.json with INDEPENDENT code.

Maps what phase 1 of a zkp_req request established (plan functions per query, the credential that
will be proved, the trust outcome, the resolved verifier_id and its type, the request's verified
client-id display name, the attested origin) to the LOCALE-FREE consent request: item kinds, config,
scope, remappable flags, age bounds as dates and integers. Both SDKs generate their text from the
same items and test against this file. It neither calls nor imports the Kotlin implementation.

Item semantics (the generator is the reference):
  - items are in the plan's function order; claims of a legacy function are one item each, then the
    legacy pseudonym when requested.
  - predicate functions are DATA: `function_registry` declares each (claim: fixed path or the `claim` param;
    value type date|number|string|bool; comparisons: param name -> op; optional min_span; optional
    age_specialisation). A function's params are a conjunction of comparisons on one claim, in the
    registry's order; any other param, an operand of the wrong type, a duplicated `in` member or no
    comparison at all REFUSES the request. A function that is not in the registry (and is not a pseudonym
    or the legacy disclosure) REFUSES the request: we cannot describe what it discloses.
  - the item's claim label is the credential's OWN display label for that path (credential.claims), else null. The
    credential's metadata paths are [namespace, element]: a predicate's path (relative to the doctype namespace) also
    matches [query.namespace] + path when the query names a namespace; another namespace's claim of the same name never does.
  - an item param `source` ({"path": [claim]}, the rulebook example) is accepted when it names the function's own claim.
    (a renderer falls back to the path). Never invented.
  - age_specialisation (age_check): both bounds -> between (min_years = years(le, today), max_years =
    years(ge, today)); only `le` -> at_least(years(le, today)); only `ge` -> at_most(years(ge, today)).
    years() is the number of completed years from the date to `today`, never below 0.
  - precheck: the local satisfiability check (false = the credential definitely does not satisfy; true = holds
    OR cannot be judged: lookup "unsupported" is skipped, never guessed; an absent claim is false).
  - combined_predicate_bounds: per claim path, over functions that DECLARE min_span: lower = max ge, upper =
    min le; with both, the span (date: days inclusive, number: le - ge) must be >= the strictest declared
    min_span. Functions without min_span have no merge rule. An unreadable bound is not ok.
  - pseudonym: only per-verifier configs are modelled (known-offender-matching-ssc: the issuer can
    remap it; known-offender-matching-psc: it cannot). Any other config, a verifier_context on a
    per-verifier config, or no verifier_id: the request is REFUSED (expected "refused": true).
  - an unknown function id, a plan with no function, or an unknown/ill-formed age_check: REFUSED.
  - input.verifier_id / verifier_id_type are what the wallet resolved; a query is given the verifier_id only
    when its plan has a pseudonym or a legacy pseudonym (the wallet resolves one only then), and the
    request's verifier.verifier_id is the first such query's.
  - verifier label: trust entity name, else the verified client-id display name (null for an
    unsigned request), else the attested origin.

Usage: python3 tools/gen_circuit_zk_consent_vectors.py [--check]
"""
import json
import pathlib
import re
import sys
from datetime import date

OUT = pathlib.Path(__file__).resolve().parent.parent / "spec" / "circuit-zk-consent-vectors.json"
TODAY = "2026-10-19"
FULL_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

CONFIGS = {
    "known-offender-matching-ssc": ("per_verifier", True),
    "known-offender-matching-psc": ("per_verifier", False),
}

REGISTRY = [
    {"id": "age_check", "claim": {"path": ["birth_date"]}, "value_type": "date", "comparisons": {"ge": "ge", "le": "le"},
     "min_span": 365, "age_specialisation": True},
    # An age-specialised function that also declares eq: the age wording ("exact birth date is not shared") would be false
    # for an eq, so such a request is rendered with the generic wording (age_form null).
    {"id": "age_with_eq", "claim": {"path": ["birth_date"]}, "value_type": "date", "comparisons": {"ge": "ge", "le": "le", "eq": "eq"},
     "age_specialisation": True},
    {"id": "date_range", "claim": {"param": "claim"}, "value_type": "date", "comparisons": {"ge": "ge", "le": "le"}, "min_span": 30},
    {"id": "date_compare", "claim": {"param": "claim"}, "value_type": "date",
     "comparisons": {"eq": "eq", "ne": "ne", "lt": "lt", "le": "le", "gt": "gt", "ge": "ge", "in": "in"}},
    {"id": "number_range", "claim": {"param": "claim"}, "value_type": "number", "comparisons": {"ge": "ge", "le": "le"}, "min_span": 10},
    {"id": "number_bounds", "claim": {"param": "claim"}, "value_type": "number", "comparisons": {"gt": "gt", "lt": "lt"}},
    {"id": "string_match", "claim": {"param": "claim"}, "value_type": "string", "comparisons": {"eq": "eq", "ne": "ne", "in": "in"}},
    {"id": "flag_is", "claim": {"param": "claim"}, "value_type": "bool", "comparisons": {"eq": "eq"}},
]
REG = {r["id"]: r for r in REGISTRY}
NUMBER = re.compile(r"^-?\d+(\.\d+)?([eE][+-]?\d+)?$")


def parse_date(s):
    if not isinstance(s, str) or not FULL_DATE.match(s):
        return None
    try:
        return date.fromisoformat(s)
    except ValueError:
        return None


def years(born, today):
    n = today.year - born.year - ((today.month, today.day) < (born.month, born.day))
    return max(0, n)


def num(s):
    # Exact rational arithmetic: Decimal subtraction would round to 28 digits, Kotlin's BigDecimal does not.
    from decimal import Decimal
    from fractions import Fraction
    return Fraction(Decimal(s)) if isinstance(s, str) and NUMBER.match(s) else None


def operand(vt, v):
    """An operand as text of the value type, or None. JSON booleans/numbers arrive as Python bool/int/float."""
    if vt == "date":
        return v if isinstance(v, str) and parse_date(v) else None
    if vt == "string":
        return v if isinstance(v, str) else None
    if vt == "bool":
        return ("true" if v else "false") if isinstance(v, bool) else None
    if vt == "number":
        if isinstance(v, bool) or isinstance(v, str) or not isinstance(v, (int, float)):
            return None
        return json.dumps(v)
    return None


def parse_fn(reg, fn):
    """(claim path, conditions) or None."""
    p = fn.get("params", {})
    if "param" in reg["claim"]:
        c = p.get("claim")
        if isinstance(c, str) and c:
            path = [c]
        elif isinstance(c, list) and c and all(isinstance(x, str) and x for x in c):
            path = c
        else:
            return None
    else:
        path = reg["claim"]["path"]
    allowed = set(reg["comparisons"]) | {"source"} | ({"claim"} if "param" in reg["claim"] else set())
    if any(k not in allowed for k in p):
        return None
    # The rulebook example's item `source` ({"path": [claim]}) is accepted only when it names the function's own claim.
    if "source" in p:
        src = p["source"]
        if not isinstance(src, dict) or set(src) != {"path"} or src["path"] != path:
            return None
    conds = []
    for param, op in reg["comparisons"].items():
        if param not in p:
            continue
        raw = p[param]
        if op == "in":
            if not isinstance(raw, list) or not raw:
                return None
            vals = [operand(reg["value_type"], x) for x in raw]
            if any(v is None for v in vals) or len(set(vals)) != len(vals):
                return None
        else:
            v = operand(reg["value_type"], raw)
            if v is None:
                return None
            vals = [v]
        conds.append({"op": op, "values": vals})
    return (path, conds) if conds else None


def age_form(conds, today):
    # The age wording is used ONLY when every condition is a single ge or le bound.
    if not conds or any(c["op"] not in ("ge", "le") for c in conds) or \
            sum(c["op"] == "ge" for c in conds) > 1 or sum(c["op"] == "le" for c in conds) > 1:
        return None
    ge = next((c["values"][0] for c in conds if c["op"] == "ge"), None)
    le = next((c["values"][0] for c in conds if c["op"] == "le"), None)
    gd, ld = parse_date(ge), parse_date(le)
    if gd and ld:
        return {"kind": "between", "from": ge, "to": le, "min_years": years(ld, today), "max_years": years(gd, today)}
    if ld:
        return {"kind": "at_least", "years": years(ld, today)}
    if gd:
        return {"kind": "at_most", "years": years(gd, today)}
    return None


def predicate_item(fn, claims, today, namespace=None):
    reg = REG.get(fn["id"])
    if reg is None:
        return None
    parsed = parse_fn(reg, fn)
    if parsed is None:
        return None
    path, conds = parsed
    label = next((c.get("label") for c in claims if c["path"] == path or (namespace is not None and c["path"] == [namespace] + path)), None)
    label = label if label and label.strip() else None
    return {"kind": "predicate", "function": fn["id"], "claim": {"path": path, "label": label}, "value_type": reg["value_type"],
            "conditions": conds, "age_form": age_form(conds, today) if reg.get("age_specialisation") else None}


def items_of(plan, verifier_id, today, claims=(), namespace=None):
    today = date.fromisoformat(today)
    out = []
    for f in plan:
        p = f.get("params", {})
        if f["id"] == "pseudonym":
            cfg = p.get("config")
            if cfg not in CONFIGS:
                return None
            scope, remap = CONFIGS[cfg]
            ctx = p.get("verifier_context")
            if scope == "per_verifier" and ctx is not None:
                return None
            if not verifier_id:
                return None
            out.append({"kind": "pseudonym", "config": cfg, "scope": scope, "remappable_by_issuer": remap,
                        "cross_site": scope == "cross_site", "verifier_id": verifier_id, "verifier_context": ctx})
        elif f["id"] == "zk-claim-disclosure-v1":
            for c in p["claims"]:
                out.append({"kind": "claim", "name": c})
            if p.get("pseudonym"):
                out.append({"kind": "legacy_pseudonym", "verifier_context": p.get("verifier_context")})
        else:
            it = predicate_item(f, claims, today, namespace)
            if it is None:
                return None
            out.append(it)
    return out or None


def label(trust, client_name, origin):
    for v in (trust.get("entity_name"), client_name):
        if v and v.strip():
            return v
    return origin


def fn(id_, handle, **params):
    return {"id": id_, "handle": handle, "params": params}


SSC = fn("pseudonym", "n", config="known-offender-matching-ssc", ver=1, prf="sha-256")
PSC = fn("pseudonym", "n", config="known-offender-matching-psc", ver=1, prf="sha-256")
LEGACY = fn("zk-claim-disclosure-v1", "d", claims=["family_name", "given_name"], systems=[{"id": "c", "system": "longfellow-libzk-v1"}])
LEGACY_PSEUDO = fn("zk-claim-disclosure-v1", "d", claims=["age_over_18"], systems=[{"id": "c", "system": "longfellow-libzk-v1"}],
                   pseudonym=True, verifier_context="ctx-1")
LONG_DID = "did:web:verifier.example.org:very:long:path:segment:identifying:this:verifier"
CRED = {"name": "Nym credential", "issuer": "Example Issuer"}
TRUST = {"entity_name": "Example RP", "framework": "etsi-tl", "identifier": "rp.example", "intermediary_risk": False}


def case(name, queries, verifier_id="rp.example", verifier_id_type="x509_san_dns", trust=TRUST, client_name="rp.example",
         origin="https://rp.example", today=TODAY, claims=(), namespace=None):
    """queries: list of (plan functions, credential). verifier_id applies to every query that has a pseudonym.
    claims: the credentials' own claim display metadata (the same for every query)."""
    qs = [dict({"plan": plan, "credential": cred, "claims": list(claims)}, **({"namespace": namespace} if namespace else {})) for plan, cred in queries]
    entries = []
    refused = not queries  # an empty query list is refused
    for plan, cred in queries:
        items = items_of(plan, verifier_id, today, claims, namespace)
        if items is None:
            refused = True
            break
        entries.append({"credential": cred, "items": items})
    exp = {"refused": True} if refused else {"request": {
        "verifier": {
            "label": label(trust, client_name, origin),
            "trust_framework": trust.get("framework"), "trust_identifier": trust.get("identifier"),
            "verifier_id": verifier_id if any(i["kind"] == "pseudonym" for e in entries for i in e["items"]) or
            any(f["id"] == "zk-claim-disclosure-v1" and f["params"].get("pseudonym") for q, _ in queries for f in q) else None,
            "verifier_id_type": verifier_id_type,
            "intermediary_risk": bool(trust.get("intermediary_risk")),
        },
        "entries": entries, "request_signed": True,
    }}
    return {"name": name, "today": today,
            "input": {"queries": qs, "trust": trust, "verified_client_id_display_name": client_name, "attested_origin": origin,
                      "verifier_id": verifier_id, "verifier_id_type": verifier_id_type},
            "expected": exp}


def age(**p): return fn("age_check", "a", **p)


def pred(id_, **p): return fn(id_, "p", **p)


CASES = [
    case("ssc pseudonym: per verifier, the issuer can remap it", [([SSC], CRED)]),
    case("psc pseudonym: per verifier, the issuer cannot remap it", [([PSC], CRED)]),
    case("pseudonym and age keep the plan's order", [([SSC, age(ge="1990-01-01", le="2008-10-19")], CRED)]),
    case("age first, then pseudonym", [([age(ge="1990-01-01", le="2008-10-19"), SSC], CRED)]),
    case("age: both bounds", [([age(ge="1990-01-01", le="2008-10-19")], CRED)]),
    case("age: at least (only le); birthday is today", [([age(le="2008-10-19")], CRED)]),
    case("age: at least, birthday is tomorrow (one year less)", [([age(le="2008-10-20")], CRED)]),
    case("age: at most (only ge)", [([age(ge="2000-01-01")], CRED)]),
    case("age: leap-day bound", [([age(le="2008-02-29")], CRED)]),
    case("age: bound in the future clamps to 0", [([age(le="2030-01-01")], CRED)]),
    case("age: other today", [([age(ge="1990-01-01", le="2008-10-19")], CRED)], today="2027-10-18"),
    case("age: no bound is refused", [([age()], CRED)]),
    case("age: unknown parameter is refused", [([age(ge="2000-01-01", gt="1999-01-01")], CRED)]),
    case("age: malformed date is refused", [([age(ge="2000-1-1")], CRED)]),
    case("age: impossible date is refused", [([age(ge="2000-02-30")], CRED)]),
    case("pseudonym without a verifier_id is refused", [([SSC], CRED)], verifier_id=None, verifier_id_type=None),
    case("account-recovery-ssc is not modelled: refused", [([fn("pseudonym", "n", config="account-recovery-ssc", verifier_context="acct")], CRED)]),
    case("user-managed-pseudonym-xsite-ssc is not modelled: refused", [([fn("pseudonym", "n", config="user-managed-pseudonym-xsite-ssc")], CRED)]),
    case("a verifier_context on a per-verifier config is refused", [([fn("pseudonym", "n", config="known-offender-matching-ssc", verifier_context="x")], CRED)]),
    case("unknown config is refused", [([fn("pseudonym", "n", config="nope")], CRED)]),
    case("unknown function is refused", [([fn("mystery", "m")], CRED)]),
    case("empty plan is refused", [([], CRED)]),
    case("an empty query list is refused", []),
    case("age wording only for single ge/le bounds: ge and le render as an age", [([pred("age_with_eq", ge="1990-01-01", le="2008-10-19")], CRED)]),
    case("age wording only for single ge/le bounds: only le still renders as an age", [([pred("age_with_eq", le="2008-10-19")], CRED)]),
    case("age wording only for single ge/le bounds: le plus eq renders generically (eq reveals the date)",
         [([pred("age_with_eq", le="2008-10-19", eq="2000-01-01")], CRED)]),
    case("age wording only for single ge/le bounds: eq alone renders generically", [([pred("age_with_eq", eq="2000-01-01")], CRED)]),
    case("age_check does not declare eq: refused", [([age(le="2008-10-19", eq="2000-01-01")], CRED)]),
    case("legacy claim disclosure lists the claim names", [([LEGACY], CRED)], verifier_id=None, verifier_id_type=None),
    case("legacy claim disclosure with a pseudonym", [([LEGACY_PSEUDO], CRED)]),
    case("two queries: one request, both queries' items", [([SSC], CRED), ([age(le="2008-10-19")], {"name": "Other", "issuer": None})]),
    case("credential without a name or issuer", [([SSC], {"name": None, "issuer": None})]),
    case("label: trust entity name wins", [([SSC], CRED)], client_name="client.example"),
    case("label: verified client-id display name when the trust decision has no name", [([SSC], CRED)],
         trust={"entity_name": None, "framework": "etsi-tl", "identifier": "rp.example"}),
    case("label: blank entity name is no name", [([SSC], CRED)],
         trust={"entity_name": "  ", "framework": None, "identifier": None}),
    case("label: attested origin for an unsigned request (client id is unauthenticated)", [([SSC], CRED)],
         trust={"entity_name": None, "framework": None, "identifier": None}, client_name=None),
    case("a long DID verifier id is carried whole", [([SSC], CRED)], verifier_id=LONG_DID, verifier_id_type="semantic"),
    case("intermediary risk flag", [([SSC], CRED)], trust=dict(TRUST, intermediary_risk=True)),
    # --- predicates over any claim (the function set is open-ended) ---
    case("numeric range on another claim, with the credential's own label", [([pred("number_range", claim="score", ge=10, le=20)], CRED)],
         claims=[{"path": ["score"], "label": "Credit score"}]),
    case("a label from the credential's [namespace, element] metadata when the namespace is the doctype's",
         [([pred("number_range", claim="score", ge=10, le=20)], CRED)], namespace="org.example.nym.1",
         claims=[{"path": ["org.example.nym.1", "score"], "label": "Credit score"}]),
    case("another namespace's claim of the same name is never the label",
         [([pred("number_range", claim="score", ge=10, le=20)], CRED)], namespace="org.example.nym.1",
         claims=[{"path": ["org.example.other", "score"], "label": "Other score"}]),
    case("a source naming the claim is accepted (rulebook example item)", [([fn("age_check", "a", ge="2008-10-10", le="2013-10-09", source={"path": ["birth_date"]})], CRED)]),
    case("a source naming another claim is refused", [([fn("age_check", "a", ge="2008-10-10", le="2013-10-09", source={"path": ["other"]})], CRED)]),
    case("numeric range: no display label, the path is the fallback", [([pred("number_range", claim="score", ge=10.5, le=99)], CRED)]),
    case("numeric range: a blank label is no label", [([pred("number_range", claim="score", ge=10, le=20)], CRED)], claims=[{"path": ["score"], "label": " "}]),
    case("numeric bounds: gt and lt", [([pred("number_bounds", claim="score", gt=0, lt=100)], CRED)]),
    case("numeric: a string operand is refused", [([pred("number_range", claim="score", ge="10", le=20)], CRED)]),
    case("numeric: an operand that is not a number is refused", [([pred("number_range", claim="score", ge=True, le=20)], CRED)]),
    case("equality on a string claim", [([pred("string_match", claim="country", eq="SE")], CRED)], claims=[{"path": ["country"], "label": "Country"}]),
    case("set membership on a string claim", [([pred("string_match", claim="country", **{"in": ["SE", "FI", "NO"]})], CRED)]),
    case("string: inequality and membership together", [([pred("string_match", claim="country", ne="DK", **{"in": ["SE", "FI"]})], CRED)]),
    case("string: an empty set is refused", [([pred("string_match", claim="country", **{"in": []})], CRED)]),
    case("string: a duplicated set member is refused", [([pred("string_match", claim="country", **{"in": ["SE", "SE"]})], CRED)]),
    case("string: a non-array set is refused", [([pred("string_match", claim="country", **{"in": "SE"})], CRED)]),
    case("boolean equality", [([pred("flag_is", claim="resident", eq=True)], CRED)], claims=[{"path": ["resident"], "label": "Resident"}]),
    case("a date claim that is not birth_date renders generically, not as an age", [([pred("date_range", claim="issue_date", ge="2020-01-01", le="2024-12-31")], CRED)],
         claims=[{"path": ["issue_date"], "label": "Issue date"}]),
    case("date claim: equal to a date (renderers use the date-specific wording for value_type date)", [([pred("date_compare", claim="issue_date", eq="2024-03-01")], CRED)],
         claims=[{"path": ["issue_date"], "label": "Issue date"}]),
    case("date claim: not equal to a date", [([pred("date_compare", claim="issue_date", ne="2024-03-01")], CRED)],
         claims=[{"path": ["issue_date"], "label": "Issue date"}]),
    case("date claim: before a date", [([pred("date_compare", claim="issue_date", lt="2024-03-01")], CRED)],
         claims=[{"path": ["issue_date"], "label": "Issue date"}]),
    case("date claim: on or before a date", [([pred("date_compare", claim="issue_date", le="2024-03-01")], CRED)],
         claims=[{"path": ["issue_date"], "label": "Issue date"}]),
    case("date claim: after a date", [([pred("date_compare", claim="issue_date", gt="2024-03-01")], CRED)],
         claims=[{"path": ["issue_date"], "label": "Issue date"}]),
    case("date claim: on or after a date", [([pred("date_compare", claim="issue_date", ge="2024-03-01")], CRED)],
         claims=[{"path": ["issue_date"], "label": "Issue date"}]),
    case("date claim: one of several dates", [([pred("date_compare", claim="issue_date", **{"in": ["2024-03-01", "2024-04-01", "2024-05-01"]})], CRED)],
         claims=[{"path": ["issue_date"], "label": "Issue date"}]),
    case("date claim: an operand that is not a full-date is refused", [([pred("date_compare", claim="issue_date", ge="2024-3-1")], CRED)]),
    case("number claim: the same comparison stays number-typed (not the date wording)", [([pred("number_bounds", claim="score", gt=10, lt=20)], CRED)],
         claims=[{"path": ["score"], "label": "Score"}]),
    case("a nested claim path (array claim param)", [([pred("string_match", claim=["address", "country"], eq="SE")], CRED)],
         claims=[{"path": ["address", "country"], "label": "Country of residence"}]),
    case("an empty claim param is refused", [([pred("string_match", claim="", eq="SE")], CRED)]),
    case("a missing claim param is refused", [([pred("string_match", eq="SE")], CRED)]),
    case("an undeclared param is refused", [([pred("string_match", claim="country", eq="SE", gt="A")], CRED)]),
    case("an unknown function is refused", [([pred("mystery_check", claim="x", eq="y")], CRED)]),
    case("a known predicate beside an unknown function: the request is refused", [([pred("string_match", claim="country", eq="SE"), fn("mystery", "m")], CRED)]),
    case("pseudonym, age and another claim's predicate, in the plan's order", [([SSC, age(le="2008-10-19"), pred("string_match", claim="country", eq="SE")], CRED)]),
]

# Display shortening of a verifier_id (the value used for hashing is never altered): more than 40 code points
# keeps the first 18 and the last 18 joined by U+2026; 40 or fewer is shown whole. Counts are code points.
SHORTENING = [
    {"id": "rp.example", "display": "rp.example"},
    {"id": "a" * 40, "display": "a" * 40},
    {"id": "a" * 41, "display": "a" * 18 + "…" + "a" * 18},
    {"id": LONG_DID, "display": LONG_DID[:18] + "…" + LONG_DID[-18:]},
    {"id": "\U0001F600" * 41, "display": "\U0001F600" * 18 + "…" + "\U0001F600" * 18},
]


def combined_ok(plans):
    """Per claim path, over functions that declare min_span: lower = max ge, upper = min le; with both, the span
    must be >= the strictest declared min_span. An unreadable bound is not ok."""
    groups = {}
    for plan in plans:
        for f in plan:
            reg = REG.get(f["id"])
            if reg is None or "min_span" not in reg:
                continue
            parsed = parse_fn(reg, f)
            if parsed is None:
                return False
            path, conds = parsed
            g = groups.setdefault(tuple(path), {"lo": None, "hi": None, "min": 0, "vt": reg["value_type"]})
            g["min"] = max(g["min"], reg["min_span"])
            conv = parse_date if g["vt"] == "date" else num
            for c in conds:
                v = conv(c["values"][0])
                if c["op"] == "ge" and (g["lo"] is None or v > g["lo"]):
                    g["lo"] = v
                if c["op"] == "le" and (g["hi"] is None or v < g["hi"]):
                    g["hi"] = v
    for g in groups.values():
        if g["lo"] is None or g["hi"] is None:
            continue
        span = (g["hi"] - g["lo"]).days + 1 if g["vt"] == "date" else (g["hi"] - g["lo"])
        if span < g["min"]:
            return False
    return True


COMBINED = [
    {"name": "no predicates", "plans": [[SSC]]},
    {"name": "one query, one-sided", "plans": [[age(le="2008-10-19")]]},
    {"name": "two queries that together pin the date: ge=D and le=D", "plans": [[age(ge="2000-01-01")], [age(le="2000-01-01")]]},
    {"name": "two queries leaving exactly 365 days", "plans": [[age(ge="2000-01-01")], [age(le="2000-12-30")]]},
    {"name": "two queries leaving 364 days", "plans": [[age(ge="2000-01-01")], [age(le="2000-12-29")]]},
    {"name": "wide intersection", "plans": [[age(ge="1990-01-01")], [age(le="2008-10-19")]]},
    {"name": "an unreadable bound is not ok", "plans": [[age(ge="2000-1-1")], [age(le="2008-10-19")]]},
    {"name": "a numeric claim: width exactly the declared minimum", "plans": [[pred("number_range", claim="score", ge=10)], [pred("number_range", claim="score", le=20)]]},
    {"name": "a numeric claim: one less than the declared minimum", "plans": [[pred("number_range", claim="score", ge=10)], [pred("number_range", claim="score", le=19)]]},
    {"name": "a numeric claim: pinned to one value", "plans": [[pred("number_range", claim="score", ge=15)], [pred("number_range", claim="score", le=15)]]},
    {"name": "a numeric claim: width 2^64 is wider than any minimum (never narrowed to a 64-bit integer)",
     "plans": [[pred("number_range", claim="score", ge=0)], [pred("number_range", claim="score", le=18446744073709551616)]]},
    {"name": "a numeric claim: exact arithmetic, a tiny lower bound does not round the span up to the minimum",
     "plans": [[pred("number_range", claim="score", ge=1e-100)], [pred("number_range", claim="score", le=10)]]},
    {"name": "different claims do not merge", "plans": [[pred("number_range", claim="score", ge=15)], [pred("number_range", claim="other", le=15)]]},
    {"name": "a date claim other than birth_date, declared minimum 30 days", "plans": [[pred("date_range", claim="issue_date", ge="2024-01-01")], [pred("date_range", claim="issue_date", le="2024-01-30")]]},
    {"name": "the same, 29 days", "plans": [[pred("date_range", claim="issue_date", ge="2024-01-01")], [pred("date_range", claim="issue_date", le="2024-01-29")]]},
    {"name": "two functions on one claim: the strictest declared minimum applies",
     "plans": [[age(ge="2000-01-01")], [pred("date_range", claim="birth_date", le="2000-06-30")]]},
    {"name": "a function that declares no minimum has no merge rule", "plans": [[pred("string_match", claim="country", eq="SE")], [pred("string_match", claim="country", eq="FI")]]},
    {"name": "equality pinned across functions without a declared minimum", "plans": [[pred("number_bounds", claim="score", gt=5)], [pred("number_bounds", claim="score", lt=6)]]},
]
for c in COMBINED:
    c["expected_ok"] = combined_ok(c["plans"])


def holds(vt, conds, value):
    if value["type"] != vt:
        return False
    conv = {"date": parse_date, "number": num}.get(vt, lambda x: x)
    v = conv(value["text"])
    for c in conds:
        ops = [conv(x) for x in c["values"]]
        r = {"eq": v == ops[0], "ne": v != ops[0], "in": v in ops, "lt": vt in ("date", "number") and v < ops[0],
             "le": vt in ("date", "number") and v <= ops[0], "gt": vt in ("date", "number") and v > ops[0],
             "ge": vt in ("date", "number") and v >= ops[0]}[c["op"]]
        if not r:
            return False
    return True


def precheck_expected(functions, lookups):
    """true: holds or cannot be judged; false: definitely not."""
    for f, lk in zip(functions, lookups):
        reg = REG[f["id"]]
        parsed = parse_fn(reg, f)
        if parsed is None:
            return False
        if lk["lookup"] == "absent":
            return False
        if lk["lookup"] == "unsupported":
            continue
        if not holds(reg["value_type"], parsed[1], {"type": lk["type"], "text": lk["text"]}):
            return False
    return True


def found(t, text): return {"lookup": "found", "type": t, "text": text}


PRECHECK = [
    {"name": "age: birth date inside the range", "functions": [age(ge="1999-01-01", le="2005-01-01")], "claims": [found("date", "2000-06-15")]},
    {"name": "age: birth date before the range", "functions": [age(ge="2001-01-01", le="2005-01-01")], "claims": [found("date", "2000-06-15")]},
    {"name": "age: bounds are inclusive (ge)", "functions": [age(ge="2000-06-15", le="2005-01-01")], "claims": [found("date", "2000-06-15")]},
    {"name": "age: bounds are inclusive (le)", "functions": [age(ge="1990-01-01", le="2000-06-15")], "claims": [found("date", "2000-06-15")]},
    {"name": "age: the claim is absent", "functions": [age(ge="1999-01-01", le="2005-01-01")], "claims": [{"lookup": "absent"}]},
    {"name": "age: the claim has another type", "functions": [age(ge="1999-01-01", le="2005-01-01")], "claims": [found("string", "2000-06-15")]},
    {"name": "number in range", "functions": [pred("number_range", claim="score", ge=10, le=20)], "claims": [found("number", "15")]},
    {"name": "number below range", "functions": [pred("number_range", claim="score", ge=10, le=20)], "claims": [found("number", "5")]},
    {"name": "number: decimal compare", "functions": [pred("number_range", claim="score", ge=10.5, le=20)], "claims": [found("number", "10.50")]},
    {"name": "number: gt is strict", "functions": [pred("number_bounds", claim="score", gt=5, lt=10)], "claims": [found("number", "5")]},
    {"name": "number: lt is strict", "functions": [pred("number_bounds", claim="score", gt=5, lt=10)], "claims": [found("number", "9")]},
    {"name": "string equality holds", "functions": [pred("string_match", claim="country", eq="SE")], "claims": [found("string", "SE")]},
    {"name": "string equality is exact (case)", "functions": [pred("string_match", claim="country", eq="SE")], "claims": [found("string", "se")]},
    {"name": "string membership holds", "functions": [pred("string_match", claim="country", **{"in": ["SE", "FI"]})], "claims": [found("string", "FI")]},
    {"name": "string membership fails", "functions": [pred("string_match", claim="country", **{"in": ["SE", "FI"]})], "claims": [found("string", "NO")]},
    {"name": "string inequality fails", "functions": [pred("string_match", claim="country", ne="SE")], "claims": [found("string", "SE")]},
    {"name": "bool equality holds", "functions": [pred("flag_is", claim="resident", eq=True)], "claims": [found("bool", "true")]},
    {"name": "bool equality fails", "functions": [pred("flag_is", claim="resident", eq=True)], "claims": [found("bool", "false")]},
    {"name": "date claim other than birth_date", "functions": [pred("date_range", claim="issue_date", ge="2020-01-01", le="2024-12-31")], "claims": [found("date", "2022-03-01")]},
    {"name": "an unsupported claim path is skipped, not guessed", "functions": [pred("string_match", claim=["address", "country"], eq="SE")], "claims": [{"lookup": "unsupported"}]},
    {"name": "every function must hold", "functions": [age(ge="1999-01-01", le="2005-01-01"), pred("string_match", claim="country", eq="SE")],
     "claims": [found("date", "2000-06-15"), found("string", "FI")]},
    {"name": "one function unsupported, the other decides", "functions": [pred("string_match", claim=["a", "b"], eq="x"), age(ge="2001-01-01", le="2005-01-01")],
     "claims": [{"lookup": "unsupported"}, found("date", "2000-06-15")]},
]
for c in PRECHECK:
    c["expected"] = precheck_expected(c["functions"], c["claims"])


def build():
    return {
        "status": "self-generated; the Kotlin and Swift SDKs test against this file byte-for-byte",
        "generator": "tools/gen_circuit_zk_consent_vectors.py",
        "note": "Locale-free: the SDK-owned wording is generated from these items and is not part of this file.",
        "function_registry": REGISTRY,
        "cases": CASES,
        "verifier_id_shortening": SHORTENING,
        "combined_predicate_bounds": COMBINED,
        "precheck": PRECHECK,
    }


if __name__ == "__main__":
    text = json.dumps(build(), indent=2, ensure_ascii=False) + "\n"
    if "--check" in sys.argv:
        sys.exit(0 if OUT.read_text() == text else "vectors out of date")
    OUT.write_text(text)
