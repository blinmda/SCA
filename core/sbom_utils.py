import subprocess
import os

def merge_sbom(sboms, output):
    cmd = [
        os.getenv("cyclonedx_path"), "merge",
        "--input-files", *sboms,
        "--output-file", output,
        "--output-version", "v1_6"
    ]

    try:
        subprocess.run(cmd, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Ошибка при выполнении cyclonedx: {e}")
        print(f"stderr: {e.stderr}")
        return None
    except FileNotFoundError:
        print("Ошибка: cyclonedx не найден.")
        return None