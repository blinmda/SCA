import argparse
import glob
import os
import graph
import report
import git

def cleanup_tmp_files(directory):
    pattern = os.path.join(directory, "*_tmp*")
    tmp_files = glob.glob(pattern)
    if not tmp_files:
        return
    for file_path in tmp_files:
        try:
            os.remove(file_path)
            print(f"Удален: {file_path}")
        except OSError as e:
            print(f"Ошибка при удалении {file_path}: {e}")


def build_parser():
    parser = argparse.ArgumentParser(description='SCA')
    subparsers = parser.add_subparsers(dest='command', required=True)

    def add_common_args(p):
        group_src = p.add_mutually_exclusive_group(required=True)
        group_src.add_argument('--dir', help='Путь к директории с исходным кодом')
        group_src.add_argument('--repo', help='Ссылка на репозиторий git')
        p.add_argument('--branch', required=False, help='Ветка git')
        p.add_argument('--dev', action='store_true', required=False, help='Включение анализа devDependencies')
        p.add_argument('--tmp', action='store_true', required=False, help='Отключение удаления временных файлов (sbom)')

    report_parser = subparsers.add_parser('report', help='Формирование отчета')
    add_common_args(report_parser)
    report_parser.add_argument('--vuln', action='store_true', help='Использование SCA анализатора trivy')
    report_parser.add_argument('--cvss', type=float, default=5, help='Нижняя граница CVSS (по умолчанию 5)')

    graph_parser = subparsers.add_parser('graph', help='Построение графа для одной зависимости')
    add_common_args(graph_parser)
    graph_parser.add_argument('name', help='Имя пакета')
    graph_parser.add_argument('version', help='Версия пакета')
    graph_parser.add_argument('--interactive',  action='store_true', help='Создание интерактивно графа')
    
    return parser

def main():
    parser = build_parser()
    args = parser.parse_args()
    
    if args.repo:
        src_dir = git.clone_repo(args.repo, args.branch)
    else:
        src_dir = args.dir
    
    if args.command == 'report':
        print(f"REPORT: обработка директории {src_dir}")
        
        data = report.parse_reports(src_dir, args.cvss, args.vuln)
        #добавить возможность выбирать триви или cdxgen для sbom
        sbom_file = graph.run_trivy(src_dir, os.path.basename(os.path.normpath(src_dir)), args.dev, False)
        report.create_vulnerability_report(data, sbom_file, os.path.basename(os.path.normpath(src_dir)))
        
    elif args.command == 'graph':
        print(f"GRAPH: обработка директории {src_dir}")
        print(f"Имя пакета: {args.name}, Версия: {args.version}")
        
        sbom_file = graph.run_trivy(src_dir, os.path.basename(os.path.normpath(src_dir)), args.dev, False)
        graph.build_tree(sbom_file, args.name, args.version, True, args.interactive)
    
    if not args.tmp:
        cleanup_tmp_files(os.getcwd())
    return 

if __name__ == "__main__":
    main()