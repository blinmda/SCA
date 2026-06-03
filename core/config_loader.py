import json
from pathlib import Path


CONFIG_FILE = Path("projects.json")


def load_projects():
    with open(CONFIG_FILE, encoding="utf-8") as f:
        return json.load(f)

def get_project(name):
    projects = load_projects()

    for project in projects:
        if project["project_name"] == name:
            return project

    raise ValueError(f"Project '{name}' not found")

def get_project_names():
    return [p["project_name"] for p in load_projects()]

def parse_project_info(project):
    project_name = project["project_name"]
    project_id = project["project_id"]
    subprojects = project.get("subprojects", [])

    repos_info = []
    for sub in subprojects:
        git = sub.get("git")
        if git:  
            branch = sub.get("branch", None)  
            repos_info.append((git, branch))

    return project_name, project_id, repos_info