"""Business layer: turn a raw tech list into a sales-ready lead record.

Primary filter  : Shopify stores, and which Shopify analytics / attribution apps they run
                  (the tools our client's plugin directly replaces).
Secondary filter: analytics used on other platforms / CMSs (future migration targets,
                  or stores that may move to Shopify).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from . import CONFIG_DIR

SEGMENTS = {
    "A": "Shopify + direct competitor (switch campaign)",
    "B": "Shopify + generic analytics only (upgrade campaign)",
    "C": "Shopify, no 3rd-party analytics found (greenfield)",
    "D": "Other ecommerce platform + analytics (secondary)",
    "E": "Other CMS / site + analytics (secondary)",
    "F": "No relevant signal / unreachable",
}


@dataclass
class Competitive:
    platform: str = ""
    is_shopify: bool = False
    segment: str = "F"
    segment_label: str = SEGMENTS["F"]
    lead_score: int = 0
    competitors: dict[str, list[str]] = field(default_factory=dict)  # tier -> tools
    pitch: str = ""
    proof: list[str] = field(default_factory=list)


class CompetitorMap:
    def __init__(self, path=None):
        cfg = json.loads((path or CONFIG_DIR / "competitors.json").read_text("utf-8"))
        self.shopify = set(cfg["shopify_platform"])
        self.other_ecom = list(cfg["other_ecommerce_platforms"])
        self.tiers = cfg["tiers"]
        self.tool_to_tier = {t: k for k, v in self.tiers.items() for t in v["tools"]}
        self.app_store_handles: dict[str, str] = cfg.get("app_store_handles", {})

    def evaluate(self, techs: dict, cms_names: list[str]) -> Competitive:
        """techs: name -> serialized detection dict (with 'evidence')."""
        c = Competitive()
        names = set(techs)
        c.is_shopify = bool(names & self.shopify)
        other = [p for p in self.other_ecom if p in names]
        c.platform = "Shopify" if c.is_shopify else (other[0] if other else (cms_names[0] if cms_names else ""))

        for name in names:
            tier = self.tool_to_tier.get(name)
            if tier:
                c.competitors.setdefault(tier, []).append(name)
        for v in c.competitors.values():
            v.sort()

        direct = c.competitors.get("shopify_analytics", [])
        generic = [t for k, v in c.competitors.items() if k != "shopify_analytics" for t in v]

        if c.is_shopify and direct:
            c.segment = "A"
        elif c.is_shopify and generic:
            c.segment = "B"
        elif c.is_shopify:
            c.segment = "C"
        elif other and (direct or generic):
            c.segment = "D"
        elif direct or generic:
            c.segment = "E"
        c.segment_label = SEGMENTS[c.segment]

        score = 0
        if c.is_shopify:
            score += 30
        elif other:
            score += 10
        for tier, tools in c.competitors.items():
            score += self.tiers[tier]["weight"] * (1 if tools else 0) + 3 * max(0, len(tools) - 1)
        c.lead_score = min(100, score)

        if c.segment == "A":
            c.pitch = f"Runs {', '.join(direct)} on Shopify - pitch migration / consolidation."
        elif c.segment == "B":
            c.pitch = f"Shopify store relying on {', '.join(generic[:3])} - pitch Shopify-native analytics upgrade."
        elif c.segment == "C":
            c.pitch = "Shopify store with no 3rd-party analytics detected - greenfield."
        elif c.segment == "D":
            c.pitch = f"{c.platform} store using {', '.join((direct + generic)[:3])} - nurture for a Shopify migration."
        elif c.segment == "E":
            c.pitch = f"{c.platform or 'Website'} using {', '.join((direct + generic)[:3])} - low priority."

        for tool in (direct + generic)[:6] + (["Shopify"] if c.is_shopify else []):
            ev = (techs.get(tool) or {}).get("evidence") or []
            if ev:
                e = ev[0]
                key = f"{e.get('key')}=" if e.get("key") else ""
                c.proof.append(f"{tool}: [{e.get('source')}] {e.get('field')} {key}{e.get('match', '')}"[:200])
            elif (techs.get(tool) or {}).get("implied_by"):
                c.proof.append(f"{tool}: implied by {', '.join(techs[tool]['implied_by'])}")
        return c
