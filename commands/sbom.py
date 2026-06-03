import os
import shutil
from core.trivy_runner import run_trivy_fs, run_trivy_git
from core.git_manager import clone_repo, create_repo_url
from core.config_loader import get_project, parse_project_info
from core.sbom_utils import merge_sbom

def run_sbom_command(dev, vuln, directory, repo, branch, clone, name, merge):

    if directory:
        out_path = run_trivy_fs(directory, dev, vuln)
        return out_path


    elif repo:
        if clone:
            target_dir = "src"
            dir = clone_repo(repo, branch, target_dir)
            out_path = run_trivy_fs(dir, dev, vuln)
        else:
            target_dir = None
            url = create_repo_url(repo)
            out_path = run_trivy_git(url, branch, dev, vuln)
        return out_path


    elif name:
        project = get_project(name)
        project_name, _, repos_info = parse_project_info(project)
        project_folder = f"./sbom/{project_name}"
        os.makedirs(project_folder, exist_ok=True)
        
        print(f"Обработка {project_name}")
        created_sboms = []
        sbom_file = None
        for git, br in repos_info:
            if clone:
                target_dir = f"src/{project_name}"
                dir = clone_repo(git, br, target_dir)
                tmp_path = run_trivy_fs(dir, dev, vuln)
            else:
                target_dir = None
                url = create_repo_url(git)
                tmp_path = run_trivy_git(url, branch, dev, vuln)
            
            out_path = os.path.join(project_folder, os.path.basename(tmp_path))
            shutil.move(tmp_path, out_path)
            created_sboms.append(out_path)

        if len(created_sboms) > 1 and merge:
            sbom_file = f"./sbom/{project_name}.json"
            merge_sbom(created_sboms, sbom_file)
            
            for old_sbom in created_sboms:
                if os.path.exists(old_sbom):
                    os.remove(old_sbom)
                    created_sboms.remove(old_sbom)
            
            created_sboms.append(sbom_file)

        return created_sboms
    
    else:
        print("Ошибка: Необходимо указать один из источников: --dir, --repo или --name")
        return []
