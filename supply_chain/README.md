# Supply chain

Каталог содержит инструменты сопровождения воспроизводимости и происхождения
сторонних компонентов проекта. Он не входит в runtime Admin Panel и Monitor.

## Состав

- `generate.py` преобразует JSON-отчёт `pip --report` в hash-locked
  requirements-файл;
- `assets.json` хранит общую provenance/license ведомость tracked binary assets;
- `licenses/` содержит зафиксированные тексты лицензий сторонних компонентов;
- `THIRD_PARTY_NOTICES.md` предоставляет пользовательскую сводку компонентов;
- `sbom.cdx.json` содержит CycloneDX inventory Python-пакетов и binary assets.

При передаче `--sbom` и `--assets` генератор объединяет сведения о
Python-пакетах и tracked binary assets в CycloneDX SBOM. Исходные requirements
и lock-файлы остаются в корне проекта, поскольку используются непосредственно
командами установки Python-окружения.
