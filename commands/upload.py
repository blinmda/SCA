import os
from core.config_loader import load_projects, get_project, parse_project_info
from core.trivy_runner import run_trivy_git
from core.sbom_utils import merge_sbom, convert_to_16
from core.dtrack_client import upload_sbom_dtrack
from core.git_manager import create_repo_url

def run_upload_command(name):
    if name:
        projects_to_upload = get_project(name)
        handle_project(projects_to_upload)
    else:
        projects_to_upload = load_projects()
        for p in projects_to_upload:
            handle_project(p)


def handle_project(project):
    project_name, project_id, repos_info = parse_project_info(project)
    print(f"\nОбработка: {project_name}")
    if not repos_info:
        print("Гиты не найдены")
        return
    
    print("Создание sbom...")
    created_sboms = []
    sbom_file = None
    for git, branch in repos_info:
        sbom_file = run_trivy_git(create_repo_url(git), branch, True, False)
        sbom_file = convert_to_16(sbom_file)    
        created_sboms.append(sbom_file)

    if len(created_sboms) > 1:
        sbom_file = f"./sbom/{project_name}_tmp.json"
        merge_sbom(created_sboms, sbom_file)
        for old_sbom in created_sboms:
            if os.path.exists(old_sbom):
                os.remove(old_sbom)

    if sbom_file is None:
        print("Не удалось сгенерировать sbom (анлак)")
        return
    
    print(f"SBOM сгенерирован {sbom_file}...")
    upload_sbom_dtrack(sbom_file, project_id)
    
    if os.path.exists(sbom_file):
        os.remove(sbom_file)


