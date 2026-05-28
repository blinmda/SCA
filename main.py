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

def main():
    parser = argparse.ArgumentParser(description='SCA')
    group_src = parser.add_mutually_exclusive_group(required=True)
    group_src.add_argument('--dir', help='Путь к директории с исходным кодом и отчетом PT AI')
    group_src.add_argument('--repo', help='Ссылка на репозиторий git')
    
    parser.add_argument('--dev', action='store_true', required=False, help='Включение анализа devDependencies')
    parser.add_argument('--tmp', action='store_true', required=False, help='Отключение удаления временных файлов (sbom)')
    parser.add_argument('--vuln', action='store_true', required=False, help='Использование SCA анализатора trivy')
    parser.add_argument('--cvss', required=False, type=float, help='Нижняя граница CVSS (по умолчанию 5)')
    parser.add_argument('--interactive',  action='store_true', required=False, help='Создание интерактивно графа')
    parser.add_argument('--branch', required=False, help='Ветка для скачивания с гита')

    group_action = parser.add_mutually_exclusive_group(required=True)
    group_action.add_argument('--report', action='store_true', help='Формирование отчета')
    group_action.add_argument('--graph', nargs=2, metavar=('NAME', 'VERSION'), 
                      help='Построение графа для одной зависимости: указывается имя и версия пакета')
    
    args = parser.parse_args()
    
    if args.repo:
        src_dir = git.clone_repo(args.repo, args.branch)
    else:
        src_dir = args.dir
    
    dev = args.dev
    if args.report:
        print(f"REPORT: обработка директории {src_dir}")
        if args.cvss:
            cvss = args.cvss
            print(f"CVSS: {cvss}")
        else: 
            cvss = 5
        
        data = report.parse_reports(src_dir, cvss, args.vuln)
        #добавить возможность выбирать триви или cdxgen для sbom
        sbom_file = graph.run_trivy(src_dir, os.path.basename(os.path.normpath(src_dir)), dev, False)
        report.create_vulnerability_report(data, sbom_file, os.path.basename(os.path.normpath(src_dir)))
        
    elif args.graph:
        name, version = args.graph
        print(f"GRAPH: обработка директории {src_dir}")
        print(f"Имя пакета: {name}, Версия: {version}")
        
        sbom_file = graph.run_trivy(src_dir, os.path.basename(os.path.normpath(src_dir)), dev, False)
        graph.build_tree(sbom_file, name, version, True, args.interactive)
    
    if not args.tmp:
        cleanup_tmp_files(os.getcwd())
    return 

if __name__ == "__main__":
    main()