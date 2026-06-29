from dotenv import load_dotenv
import argparse
from commands.sbom import run_sbom_command
from commands.upload import run_upload_command
from commands.graph import run_graph_command
from commands.report import run_report_command
from core.config_loader import get_project_names

def main():
    parser = argparse.ArgumentParser(description="SCA Security Framework CLI")
    parser.add_argument("--show", action="store_true", help="Показать список доступных проектов")
    
    subparsers = parser.add_subparsers(dest="command", help="Доступные команды")

    # --- КОМАНДА UPLOAD ---
    upload_parser = subparsers.add_parser("upload", help="Загрузка SBOM в Dependency-Track")
    upload_parser.add_argument("--name", type=str, help="Имя проекта для загрузки")

    # --- КОМАНДА SBOM ---
    sbom_parser = subparsers.add_parser("sbom", help="Генерация SBOM файла")
    sbom_parser.add_argument("--dev", action="store_true", help="Включить анализ dev-зависимостей")
    sbom_parser.add_argument("--vuln", action="store_true", help="Анализировать уязвимости в компонентах")
    source_group = sbom_parser.add_mutually_exclusive_group()
    source_group.add_argument("--dir", type=str, help="Путь до локальной директории")
    source_group.add_argument("--repo", type=str, help="Ссылка на Git-репозиторий")
    source_group.add_argument("--name", type=str, help="Имя проекта из json конфига")
    sbom_parser.add_argument("--branch", type=str, help="Ветка репозитория (только с параметром --repo)")
    sbom_parser.add_argument("--clone", action="store_true", help="Сохранить код в папку src (только с параметрами --repo и --name)")
    sbom_parser.add_argument("--merge", action="store_true", help="Объединить отчеты, если у проекта несколько репозиториев (только с параметром --name)")

    # --- КОМАНДА GRAPH ---
    graph_parser = subparsers.add_parser("graph", help="Создание графа зависимостей")
    graph_parser.add_argument("name", type=str, help="Имя пакета")
    graph_parser.add_argument("version", type=str, help="Версия пакета")
    graph_parser.add_argument("--sbom", type=str, required=True, help="Путь до сбома или директории со сбомами")
    graph_parser.add_argument("--interactive", action="store_true", help="Сделать граф интерактивным (HTML)")

    # --- КОМАНДА REPORT ---
    report_parser = subparsers.add_parser("report", help="Создание отчета уязвимостей")
    report_parser.add_argument("--sbom", type=str, required=True, help="Путь до сбома или директории со сбомами")
    report_parser.add_argument("--ptai", type=str, help="Путь до отчета PT AI")
    report_parser.add_argument("--cvss", type=float, default=5.0, help="Минимальный порог CVSS (по умолчанию 5.0)")

    args = parser.parse_args()
    
    if args.show:
        for i, name in enumerate(get_project_names(), start=1):
            print(f"{i}. {name}")
        return

    if args.command == "upload":
        run_upload_command(name=args.name)
        
    elif args.command == "sbom":
        generated_files = run_sbom_command(
            dev=args.dev, vuln=args.vuln, directory=args.dir,
            repo=args.repo, branch=args.branch, clone=args.clone,
            name=args.name, merge=args.merge
        )
        print(f"\nРезультаты сохранены в: {generated_files}")
        
    elif args.command == "graph":
        run_graph_command(pkg_name=args.name, pkg_version=args.version, sbom_path=args.sbom, interactive=args.interactive)
        
    elif args.command == "report":
        run_report_command(sbom_path=args.sbom, min_cvss=args.cvss, ptai_path=args.ptai)

if __name__ == "__main__":
    load_dotenv()
    main()
