import requests
import os

def upload_sbom_dtrack(sbom_file, project_id):
    with open(sbom_file, "rb") as f:
        print(f"Отправка {sbom_file}")
        response = requests.post(
            f"{os.getenv("DT_URL")}/api/v1/bom",
            headers={"X-Api-Key": os.getenv("DT_TOKEN")},
            files={"bom": (os.path.basename(sbom_file), f, "application/json")},
            data={"autoCreate": "true", "project": project_id}
        )

    if response.status_code in (200, 201):
        print(f"SBOM успешно загружен")
    else:
        print("Ошибка загрузки SBOM")
        print("Status:", response.status_code)
        print("Response:", response.text)

    response.raise_for_status()
