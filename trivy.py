import os
import subprocess

trivy_path = "C:\\Users\\abmnild\\Desktop\\w\\trivy\\trivy.exe"

def run_trivy_git(repo, branch, dev, vuln):
    output_file = f"{repo.rstrip("/").split("/")[-1]}_sbom_tmp.json"

    cmd = [
        trivy_path, "repo", repo,
        "--format", "cyclonedx",
        "--output", output_file
    ]
    if dev:
        cmd.append("--include-dev-deps")
    if vuln:
        cmd.extend(["--scanners", "vuln"])
    if branch:
        cmd.extend(["--branch", branch])
    try:
        subprocess.run(cmd, capture_output=True, text=True, check=True)
        return output_file
    except subprocess.CalledProcessError as e:
        print(f"Ошибка при выполнении trivy: {e}")
        print(f"stderr: {e.stderr}")
        return None
    except FileNotFoundError:
        print("Ошибка: trivy не найден.")
        return None

def run_trivy_fs(src_dir, dev, vuln):
    output_file = f"{os.path.basename(os.path.normpath(src_dir))}_sbom_tmp.json"
        
    cmd = [
        trivy_path, "fs",
        "--format", "cyclonedx",
        "--output", output_file,
        src_dir
    ]
    if dev:
        cmd.append("--include-dev-deps")
    if vuln:
        cmd.extend(["--scanners", "vuln"])

    try:
        subprocess.run(cmd, capture_output=True, text=True, check=True)
        return output_file
    except subprocess.CalledProcessError as e:
        print(f"Ошибка при выполнении trivy: {e}")
        print(f"stderr: {e.stderr}")
        return None
    except FileNotFoundError:
        print("Ошибка: trivy не найден.")
        return None
