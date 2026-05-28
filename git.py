import shutil
from dotenv import load_dotenv
from urllib.parse import urlparse
import subprocess
import os
import stat

git_path = "C:\\Program Files\\Git\\bin\\git.exe"

def make_writable_recursive(root_path):
    print(f"Удаление старой директории {root_path}...")
    for dirpath, dirnames, filenames in os.walk(root_path):
        for name in filenames:
            path = os.path.join(dirpath, name)
            os.chmod(path, os.stat(path).st_mode | stat.S_IWRITE)

        for name in dirnames:
            path = os.path.join(dirpath, name)
            os.chmod(path, os.stat(path).st_mode | stat.S_IWRITE)

    os.chmod(root_path, os.stat(root_path).st_mode | stat.S_IWRITE)

def get_creds_by_host(host):
    CONFIG = {
        "git.setl.ru": os.getenv("GITLAB_CREDS"),
        "gitlabadm1.setl.ru": os.getenv("GITADM_CREDS"),
        "git3.setl.ru":  os.getenv("GIT3_CREDS"),
        "github.com": os.getenv("GITHUB_CREDS")    
    }
    if host in CONFIG:
        return CONFIG[host]
    else:
        return None

def clone_repo(url, branch):
    load_dotenv()

    project_name = url.rstrip("/").split("/")[-1]
    project_dir = f"./src/{project_name}"
    if os.path.isdir(project_dir):
        make_writable_recursive(project_dir)
        shutil.rmtree(project_dir)

    parsed = urlparse(url)
    credentials = get_creds_by_host(parsed.netloc)
    if credentials:
        result_url = (
            f"{parsed.scheme}://{credentials}@"
            f"{parsed.netloc}{parsed.path}.git"
        )
    else:
        result_url = f"{url}.git"

    print(f"Загрузка репозитория по ссылке {url}...")
    cmd = [
        git_path, "clone",
        result_url,
        project_dir
    ]
    
    if branch:
        cmd.extend(["--branch", branch])

    try:
        subprocess.run(cmd, capture_output=True, text=True, check=True)
        print("Репозиторий скопирован (круто!)")
        return project_dir
    except subprocess.CalledProcessError as e:
        print(f"Ошибка при выполнении git: {e}")
        print(f"stderr: {e.stderr}")
        return None
    except FileNotFoundError:
        print("Ошибка: git не найден.")
        return None
