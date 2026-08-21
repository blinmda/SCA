import os
import json
from collections import defaultdict
from bs4 import BeautifulSoup
from core.dependency_tree import build_package_index, build_tree, format_paths_for_console
from core.get_version import get_fixed_version


def run_report_command(sbom_path, min_cvss, ptai_path):
    if os.path.isdir(sbom_path):
        dir_name = os.path.basename(os.path.normpath(sbom_path))
        os.makedirs(f"./reports/{dir_name}", exist_ok=True)
        for filename in os.listdir(sbom_path):
            file_path = os.path.join(sbom_path, filename)
            print(f"Обработка {file_path}")
            if os.path.isfile(file_path):
                data = parse_reports(file_path, ptai_path, min_cvss)
                create_vulnerability_report(data, file_path, f"./reports/{dir_name}/vulnerability_report_{filename.split("_tmp")[0]}.html")
    else:
        print(f"Обработка {sbom_path}")
        data = parse_reports(sbom_path, ptai_path, min_cvss)
        sbom_filename = os.path.basename(sbom_path)
        create_vulnerability_report(data, sbom_path, f"./reports/vulnerability_report_{sbom_filename.split("_tmp")[0]}.html")

def create_vulnerability_report(data, sbom_file, filename):

    html_content = f"""
    <html>
        <head>
            <style>
            table {{ border-collapse: collapse; width: 100%; }}
            th, td {{ border: 1px solid black; padding: 8px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
            td pre {{
                font-family: "Times New Roman", Times, serif;
                font-size: 18px; 
                margin: 0; 
                white-space: pre-wrap; 
                word-wrap: break-word;
            }}
            </style>
        </head>
        <body>
            <h1>Обнаруженные уязвимости</h1>
            <table>
                <tr>
                    <th>Компонент</th>
                    <th>CVE/GHSA</th>
                    <th>Max CVSS</th>
                    <th>Исправленная версия</th>
                    <th>Связь</th>
                    <th>Родительские зависимости</th>
                </tr>
    """

    items = []
    for item in data:
        display_name_full = item[0]  
        cve_links_str = item[1]      
        max_cvss = item[2]      
        purl = item[3]       

        component_name = display_name_full.split(' ')[0]
        version = display_name_full.split(' ')[1]
        all_paths, id_to_label = build_tree(sbom_file, component_name, version)
        if not all_paths or not id_to_label:
            continue
        dependency = format_paths_for_console(all_paths, id_to_label)
        
        fixed_version = "-"
        if purl:
            fixed_version = get_fixed_version(purl)

        relation = "Транзитивная"
        if any(len(path) <= 2 for path in all_paths):
            relation = "Прямая"

        items.append({
            'display_name_full': display_name_full,
            'cve_links_str': cve_links_str,
            'max_cvss': max_cvss,
            'dependency': dependency,
            'fixed': fixed_version,
            'relation': relation
        })

    special_message = "Пакет не найден в SBOM. Возможно, это dev-зависимость, используйте параметр --dev."
    normal_items = [item for item in items if item['dependency'] != special_message]
    special_items = [item for item in items if item['dependency'] == special_message]

    normal_items.sort(key=lambda x: float(x['max_cvss'].replace(',', '.')), reverse=True)
    sorted_items = normal_items + special_items


    for item in sorted_items:
        html_content += f"""
            <tr>
                <td><pre>{item['display_name_full']}</pre></td>
                <td><pre>{item['cve_links_str']}</pre></td>
                <td><pre>{item['max_cvss']}</pre></td>
                <td><pre>{item['fixed']}</pre></td>
                <td><pre>{item['relation']}</pre></td>
                <td><pre>{item['dependency']}</pre></td>
            </tr>
        """


    html_content += """
                    </table>
                </body>
            </html>
            """
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
    except IOError:
        print(f"Не удалось записать файл по пути {filename}")

    print(f"Вау!!! Отчет создан: {filename}")

def simple_sca(item):
    display_name_full = item.get("Type", {}).get("DisplayName", "")
            
    cve_links_html = []
    cvss_scores = []

    cve_descriptions = item.get("CveDescriptions", [])
            
    for cve_desc in cve_descriptions:
        cve_key = cve_desc.get("Key", "")
                
        if cve_key and cve_key.startswith("CVE-"):
            url = f"https://nvd.nist.gov/vuln/detail/{cve_key}"
            cve_links_html.append(f'<a href="{url}">{cve_key}</a>')
                
        cvss_score = "-"
                
        cvss3 = cve_desc.get("Cvss3")
        if cvss3 and isinstance(cvss3, dict):
            base_score = cvss3.get("BaseScore")
            if base_score is not None:
                try:
                    cvss_score = float(base_score)
                except (ValueError, TypeError):
                    pass
                
        if cvss_score == "-":
            cvss2 = cve_desc.get("Cvss2")
            if cvss2 and isinstance(cvss2, dict):
                base_score = cvss2.get("BaseScore")
                if base_score is not None:
                    try:
                        cvss_score = float(base_score)
                    except (ValueError, TypeError):
                        pass
                
        if cvss_score != "-":
            cvss_scores.append(cvss_score)
            
    cve_links_str = "\n".join(cve_links_html) if cve_links_html else "Нет данных"
    max_cvss = None
            
    if cvss_scores:
        max_cvss = max(cvss_scores)
    else:
        max_cvss = "-"

    return [display_name_full, cve_links_str, max_cvss, None]
    
def extended_sca(item):
    display_name_full = item.get("Type", {}).get("DisplayName", "")

    cve_links_html = []
    cvss_scores = []
        
    for pt_osv in item.get("PtOsvs", []):
        sources = pt_osv.get("Sources", [])
        cve_list = [s for s in sources if s.startswith("CVE-")]
        ghsa_list = [s for s in sources if s.startswith("GHSA-")]

        if cve_list:
            for cve in cve_list:
                ghsa = ghsa_list[0] if ghsa_list else ""
                url = f"https://github.com/advisories/{ghsa}" if ghsa else "#"
                cve_links_html.append(f'<a href="{url}">{cve}</a>')
        elif ghsa_list:
            for ghsa in ghsa_list:
                url = f"https://github.com/advisories/{ghsa}"
                cve_links_html.append(f'<a href="{url}">{ghsa}</a>')

        cvss_entries = pt_osv.get("Cvss", [])
        score = "-"
        version_priority = {"4": [], "3.1": [], "2": []}
            
        for cvss in cvss_entries:
            version = cvss.get("Version")
            cvss_score = cvss.get("Score")
            if version in version_priority and cvss_score is not None:
                version_priority[version].append(float(cvss_score))
                    
        for version in ["4", "3.1", "2"]:
            if version_priority[version]:
                score = max(version_priority[version])
                break
            
        if score != "-":
            cvss_scores.append(score)

    cve_links_str = "\n".join(cve_links_html) if cve_links_html else "Нет данных"
    max_cvss = None
        
    if cvss_scores:
        max_cvss = max(cvss_scores)
    else:
        max_cvss = "-"

    return [display_name_full, cve_links_str, max_cvss, None]

def parse_ptai(report_path):
    result = []
    
    try:
        with open(report_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"Файл не найден по пути {report_path}")
        return result
    except json.JSONDecodeError:
        print(f"Некорректный JSON файл по пути {report_path}")
        return result
    
    for item in data.get("Items", []):
        if item.get("TypeKey") == "ScaFingerprintVulnerability":
            result.append(extended_sca(item))
        elif item.get("TypeKey") == "FingerprintVulnerability":
            result.append(simple_sca(item))
        else: continue
    
    return result

def parse_trivy(report_path):
    result = []
    
    try:
        with open(report_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"Файл не найден по пути {report_path}")
        return result
    except json.JSONDecodeError:
        print(f"Некорректный JSON файл по пути {report_path}")
        return result
    
    id_to_label, label_to_purl, _, _ = build_package_index(data, None, None)

    components_vulns = defaultdict(lambda: {
        "cve_links": set(), 
        "cvss_scores": []
    })
    
    vulns_list = data.get('vulnerabilities', [])
    
    for vuln in vulns_list:
        vuln_id = vuln.get('id', '')
        
        if not vuln_id or not vuln_id.startswith('CVE-'):
            continue
        
        affects_list = vuln.get('affects', [])
        
        for affect in affects_list:
            ref = affect.get('ref', '')
            
            component_key = id_to_label[ref]

            if component_key == ref and ref.startswith('pkg:'):
                parts = ref.split('/')
                if len(parts) >= 2:
                    name_version = parts[-1]
                    if '@' in name_version:
                        name, version = name_version.split('@')
                        component_key = f"{name} {version}"
            

            url = f"https://nvd.nist.gov/vuln/detail/{vuln_id}"
            cve_link = f'<a href="{url}">{vuln_id}</a>'
            components_vulns[component_key]["cve_links"].add(cve_link)
            
            cvss_score = extract_best_cvss_score(vuln.get('ratings', []))
            if cvss_score is not None:
                components_vulns[component_key]["cvss_scores"].append(cvss_score)
    
    result = []
    
    for component_name, vuln_data in sorted(components_vulns.items()):
        cve_links_sorted = sorted(vuln_data["cve_links"])
        cve_links_str = "\n".join(cve_links_sorted) if cve_links_sorted else "Нет данных"

        if vuln_data["cvss_scores"]:
            max_cvss = max(vuln_data["cvss_scores"])
        else:
            max_cvss = "-"
        
        result.append([component_name, cve_links_str, max_cvss, label_to_purl.get(component_name)])
    
    return result

def extract_best_cvss_score(ratings):
    if not ratings:
        return None

    version_priority = {"CVSSv4": [], "CVSSv31": [], "CVSSv2": []}
    
    for rating in ratings:
        source = rating.get('source', {}).get('name', '')
        version = rating.get('method', '')
        score = rating.get('score', 0.0)
        
        if score <= 0:
            continue
        if source != 'nvd':
            continue
        
        if version and version in version_priority:
            try:
                version_priority[version].append(float(score))
            except (ValueError, TypeError):
                pass
    
    for version in ["CVSSv4", "CVSSv31", "CVSSv2"]:
        if version_priority[version]:
            return max(version_priority[version])
    
    for rating in ratings:
        score = rating.get('score', 0.0)
        if score > 0:
            try:
                return float(score)
            except (ValueError, TypeError):
                continue
    
    return None
   
def parse_reports(sbom_path, ptai_path, min_cvss):
    all_results = []

    if ptai_path:
        ptai_results = parse_ptai(ptai_path)
        all_results.extend(ptai_results)

    if sbom_path:
        trivy_results = parse_trivy(sbom_path)
        all_results.extend(trivy_results)
    
    unique = {}
    for name, cve_links_html, cvss, purl in all_results:
        if cvss == "-" or cvss is None:
            continue
        try:
            cvss_float = float(cvss)
            if cvss_float < min_cvss:
                continue
            if name not in unique:
                 unique[name] = {"cve_links": [], "cve_ids_seen": set(), "cvss": cvss_float, "purl": purl}
            
            if cve_links_html and cve_links_html != "-":
                for c in cve_links_html.split("\n"):
                    soup = BeautifulSoup(c, 'html.parser')
                    for link in soup.find_all('a'):
                        cve_id = link.text.strip()
                        if cve_id and cve_id not in unique[name]["cve_ids_seen"]:
                            unique[name]["cve_ids_seen"].add(cve_id)
                            unique[name]["cve_links"].append(str(link))
            
            unique[name]["cvss"] = max(unique[name]["cvss"], cvss_float)
        except:
            continue

    filtered_results = []
    for name, data in unique.items():
        cve_links_html = "\n".join(data["cve_links"]) if data["cve_links"] else "-"
        cvss_str = str(data["cvss"]).replace(".", ",")
        filtered_results.append([name, cve_links_html, cvss_str, data["purl"]])


    return filtered_results