import os
import subprocess

def run_trivy(cmd):
    try:
        subprocess.run(cmd, capture_output=True, text=True, check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Ошибка при выполнении trivy: {e}")
        print(f"stderr: {e.stderr}")
        return None
    except FileNotFoundError:
        print("Ошибка: trivy не найден.")
        return None

def run_trivy_git(repo, branch, dev, vuln):
    output_file = f"./sbom/{repo.rstrip("/").split("/")[-1]}_sbom_tmp.json"

    cmd = [
        os.getenv("trivy_path"), "repo", repo,
        "--format", "cyclonedx",
        "--output", output_file
    ]
    if dev:
        cmd.append("--include-dev-deps")
    if vuln:
        cmd.extend(["--scanners", "vuln"])
    if branch:
        cmd.extend(["--branch", branch])
    
    if run_trivy(cmd):
        return output_file

def run_trivy_fs(src_dir, dev, vuln):
    output_file = f"./sbom/{os.path.basename(os.path.normpath(src_dir))}_sbom_tmp.json"
        
    cmd = [
        os.getenv("trivy_path"), "fs",
        "--format", "cyclonedx",
        "--output", output_file,
        src_dir
    ]
    if dev:
        cmd.append("--include-dev-deps")
    if vuln:
        cmd.extend(["--scanners", "vuln"])

    if run_trivy(cmd):
        return output_file