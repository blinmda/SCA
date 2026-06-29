import subprocess
import os
import json

def merge_sbom(sboms, output):
    print("merge sboms...")
    cmd = [
        os.getenv("cyclonedx_path"), "merge",
        "--input-files", *sboms,
        "--output-file", output,
        "--output-version", "v1_6"
    ]

    try:
        subprocess.run(cmd, capture_output=True, text=True, check=True)
        deduplicate_dependencies(output)
    except subprocess.CalledProcessError as e:
        print(f"Ошибка при выполнении cyclonedx: {e}")
        print(f"stderr: {e.stderr}")
        return None
    except FileNotFoundError:
        print("Ошибка: cyclonedx не найден.")
        return None
    
def deduplicate_dependencies(sbom_path):
    with open(sbom_path, "r", encoding="utf-8") as f:
        sbom = json.load(f)

    fixed = 0
    for dep in sbom.get("dependencies", []):
        depends_on = dep.get("dependsOn")

        if not depends_on:
            continue

        original_len = len(depends_on)
        dep["dependsOn"] = list(dict.fromkeys(depends_on))
        fixed += original_len - len(dep["dependsOn"])

    if fixed:
        with open(sbom_path, "w", encoding="utf-8") as f:
            json.dump(sbom, f, indent=2)
    print(f"Удалено дубликатов: {fixed}")
    return

def convert_to_16(sbom_path):
    output_path = sbom_path.replace("_tmp.json", "_v16_tmp.json")
    cmd = [
        os.getenv("cyclonedx_path"), "convert",
        "--input-file", sbom_path,
        "--output-file", output_path,
        "--output-format", "json",
        "--output-version", "v1_6"
    ]

    try:
        subprocess.run(cmd, capture_output=True, text=True, check=True)
        if os.path.exists(sbom_path):
            os.remove(sbom_path)
        return output_path
    except subprocess.CalledProcessError as e:
        print(f"Ошибка при выполнении cyclonedx: {e}")
        print(f"stderr: {e.stderr}")
        return None
    except FileNotFoundError:
        print("Ошибка: cyclonedx не найден.")
        return None