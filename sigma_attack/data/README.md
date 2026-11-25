# Bundled ATT&CK catalog

`attack_catalog.json` is generated from the official MITRE ATT&CK enterprise
STIX bundle:

<https://github.com/mitre-attack/attack-stix-data>

The file stores the ATT&CK version, tactic IDs and short names, technique names,
tactic memberships, and parent technique IDs. It is bundled so mapping and
coverage reporting work offline and deterministically.

To refresh it, build a catalog from a downloaded STIX bundle:

```python
import json

from sigma_attack import AttackCatalog

catalog = AttackCatalog.from_stix("enterprise-attack.json")
with open("sigma_attack/data/attack_catalog.json", "w", encoding="utf-8") as handle:
    json.dump(catalog.to_dict(), handle, indent=1)
```

The `tactics` mapping in the bundled file uses official tactic IDs such as
`TA0002` as keys and short names such as `execution` as values.

