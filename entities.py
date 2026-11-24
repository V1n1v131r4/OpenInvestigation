"""Entity resolution: a canonical identity and alias graph from ATT&CK and MISP Galaxy.

Names and vendor aliases for the same actor/malware are linked into one canonical entity, with the
source of each alias recorded. Two catalogs naming the same thing is an overlap (expected); one
catalog giving a shared alias to two differently-named entries is flagged as a conflict. Malpedia
and ETDA are out of scope for this round (see PLAN.md), so only ATT&CK and MISP Galaxy feed this.
"""
import re

ATTACK = "MITRE ATT&CK"
GALAXY = "MISP Galaxy"


def normalize(name):
    return " ".join(re.findall(r"\w+", (name or "").casefold()))


def _entries(attack_objects, galaxy_values):
    entries = []
    for item in attack_objects or []:
        if (isinstance(item, dict) and item.get("type") in ("intrusion-set", "malware", "tool", "campaign")
                and isinstance(item.get("name"), str) and not item.get("revoked")):
            aliases = [alias for alias in (item.get("aliases") or []) if isinstance(alias, str) and alias.strip()]
            entries.append((item["name"], aliases, ATTACK))
    for row in galaxy_values or []:
        if isinstance(row, dict) and isinstance(row.get("value"), str):
            meta = row.get("meta") if isinstance(row.get("meta"), dict) else {}
            aliases = [alias for alias in (meta.get("synonyms") or []) if isinstance(alias, str) and alias.strip()]
            entries.append((row["value"], aliases, GALAXY))
    return entries


class EntityGraph:
    def __init__(self, attack_objects=None, galaxy_values=None):
        entries = _entries(attack_objects, galaxy_values)
        parent = list(range(len(entries)))

        def find(node):
            while parent[node] != node:
                parent[node] = parent[parent[node]]
                node = parent[node]
            return node

        owner = {}
        for index, (name, aliases, _) in enumerate(entries):
            for token in {normalize(name), *(normalize(alias) for alias in aliases)} - {""}:
                if token in owner:
                    parent[find(index)] = find(owner[token])
                else:
                    owner[token] = index

        components = {}
        for index in range(len(entries)):
            components.setdefault(find(index), []).append(entries[index])

        self.entities = []
        self._index = {}
        for members in components.values():
            names = {}
            per_source_canonicals = {}
            for name, aliases, source in members:
                per_source_canonicals.setdefault(source, set()).add(name)
                for value in (name, *aliases):
                    names.setdefault(value, set()).add(source)
            canonical = next((name for name, _, source in members if source == ATTACK), members[0][0])
            entity = {
                "canonical": canonical,
                "aliases": sorted(name for name in names if name != canonical),
                "sources": sorted({source for _, _, source in members}),
                "alias_sources": {name: sorted(sources) for name, sources in names.items()},
                "overlaps": len({source for _, _, source in members}) > 1,
                "conflict": any(len(values) > 1 for values in per_source_canonicals.values()),
            }
            position = len(self.entities)
            self.entities.append(entity)
            for name in names:
                self._index[normalize(name)] = position

    def resolve(self, name):
        position = self._index.get(normalize(name))
        return self.entities[position] if position is not None else None

    def conflicts(self):
        return [entity for entity in self.entities if entity["conflict"]]
