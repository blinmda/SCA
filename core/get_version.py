import argparse
import requests
from packaging.version import Version, InvalidVersion
from packageurl import PackageURL
 
OSV_URL = "https://api.osv.dev/v1/query"

ECOSYSTEMS = {
    "npm": "npm",
    "pypi": "PyPI",
    "maven": "Maven",
    "nuget": "NuGet",
    "composer": "Packagist"
}

def query_osv(package, ecosystem, version):
    r = requests.post(
        OSV_URL,
        json={
            "package": {
                "name": package,
                "ecosystem": ecosystem,
            },
            "version": version,
        },
        timeout=30,
    )

    r.raise_for_status()
    return r.json().get("vulns", [])


def query_osv_purl(purl):
    r = requests.post(
        OSV_URL,
        json={
            "package": {
                "purl": purl
            }
        },
        timeout=30,
    )

    r.raise_for_status()
    return r.json().get("vulns", [])


def first_fixed_version(vuln, current_version):
    candidates = []

    for affected in vuln.get("affected", []):
        for r in affected.get("ranges", []):
            for event in r.get("events", []):
                if "fixed" in event:
                    try:
                        candidates.append(
                            Version(event["fixed"])
                        )
                    except InvalidVersion:
                        pass

    if not candidates:
        return None
    
    try:
        major_version = Version(current_version).major
    except InvalidVersion:
        major_version = int(current_version.split(".", 1)[0])

    same_major = sorted (v for v in candidates
                         if v.major == major_version)
    if same_major:
        return same_major[0]

    newer_major = sorted (v for v in candidates
                          if v.major > major_version)
    if newer_major:
        return newer_major[0]
    
    return min(candidates)


def required_version(fixed_versions):
    if not fixed_versions:
        return None

    return max(fixed_versions)


def get_fixed_version(purl):
    vulns = query_osv_purl(purl)
    
    if not vulns:
        return (f"Уязвимости для {purl} не найдены")
    
    current_version = PackageURL.from_string(purl).version

    required = []
    for v in vulns:
        if not any(alias.startswith("CVE-") for alias in v.get("aliases", [])):
            continue
    
        fixed = first_fixed_version(v, current_version)
        if fixed:
            required.append(fixed)

    final = required_version(required)
    if final:
        return final
    else:
        return "Версия для обновления не определена"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--ecosystem",
        required=True,
        choices=ECOSYSTEMS.keys(),
    )

    parser.add_argument("package")
    parser.add_argument("version")

    args = parser.parse_args()
    ecosystem = ECOSYSTEMS[args.ecosystem]

    vulns = query_osv(
        args.package,
        ecosystem,
        args.version,
    )

    if not vulns:
        print(f"Уязвимости для {args.package}@{args.version} не найдены")
        return

    print(f"\nНайдено {len(vulns)} уязвимостей\n")

    required = []
    for v in vulns:
        if not any(alias.startswith("CVE-") for alias in v.get("aliases", [])):
            continue

        fixed = first_fixed_version(v, args.version)
        if fixed:
            required.append(fixed)

        print("=" * 70)
        print("ID:", v["id"])
        print("Aliases:", ", ".join(v.get("aliases", [])))
        if fixed:
            print("Fixed in:", fixed)
        else:
            print("Fix not found")
        print()

    print("=" * 70)
    final = required_version(required)
    if final:
        print(f"\nМинимальная рекомендуемая версия: {final}")


if __name__ == "__main__":
    main()