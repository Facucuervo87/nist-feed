import argparse
import requests
import json

parser = argparse.ArgumentParser(description='Busca vulnerabilidades del NIST.')
parser.add_argument('--cpe', metavar='cpe', type=str, help='Buscar por CPE')
parser.add_argument('--keyword', metavar='keyword', type=str, help='Buscar por palabra clave')
parser.add_argument('--repo', action='store_true', help='Mostrar solo los 3 CVE con los scores más altos')
args = parser.parse_args()

if args.cpe:
    params = {'cpeMatchString': args.cpe}
elif args.keyword:
    params = {'keyword': args.keyword}
else:
    print("Debe ingresar una opción de búsqueda")
    exit()

# Definir la URL base y los parámetros de búsqueda
url = 'https://services.nvd.nist.gov/rest/json/cves/1.0'

# Realizar la solicitud HTTP y obtener la respuesta en formato JSON
response = requests.get(url, params=params)
data = json.loads(response.content)

# Clasificar los resultados por puntaje
results = data['result']['CVE_Items']
results.sort(key=lambda x: x['impact']['baseMetricV3']['cvssV3']['baseScore'] if 'baseMetricV3' in x['impact'] else x['impact']['baseMetricV2']['cvssV2']['baseScore'], reverse=True)

# Iterar sobre los resultados y mostrar información relevante
total_cves = 0
for result in results[:3] if args.repo else results:
    total_cves += 1
    print(f"CVE ID: {result['cve']['CVE_data_meta']['ID']}")
    print(f"Descripción: {result['cve']['description']['description_data'][0]['value']}")
    if 'baseMetricV3' in result['impact']:
        print(f"CVSS Score: {result['impact']['baseMetricV3']['cvssV3']['baseScore']}")
        print(f"Vector de ataque: {result['impact']['baseMetricV3']['cvssV3']['vectorString']}")
    elif 'baseMetricV2' in result['impact']:
        print(f"CVSS Score: {result['impact']['baseMetricV2']['cvssV2']['baseScore']}")
        print(f"Vector de ataque: {result['impact']['baseMetricV2']['cvssV2']['vectorString']}")
    else:
        print("CVSSv3 y CVSSv2 no disponibles")
    cpe_json = result['configurations']['nodes']
    print('CPE afectados:')
    for e in cpe_json:
        cpe =  e['cpe_match']
        for e in cpe:
            cpe_uri = e['cpe23Uri']

            print(cpe_uri)

    reference = result['cve']['references']['reference_data']
    print('Referencias:')
    for url in reference:
        print(url['url'])
    
    print("------------------------------------------------------------------")

print(f"Total de CVEs encontrados: {total_cves}")
