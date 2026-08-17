#!/usr/bin/env python3
# cache_poisoning_validator.py
# Herramienta para detectar y validar Web Cache Poisoning en múltiples URLs

import requests
import hashlib
import time
import sys
import json
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import urlparse
import re

class CachePoisoningValidator:
    """Validador de Web Cache Poisoning con encabezados UNKEYED"""
    
    def __init__(self, verbose=True, timeout=10):
        self.verbose = verbose
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.results = []
        
        # Encabezados a probar (comunes en ataques de cache poisoning)
        self.default_headers = {
            "X-Forwarded-For": "127.0.0.1",
            "X-Forwarded-Host": "evil.com",
            "X-Forwarded-Proto": "https",
            "X-Original-URL": "/admin",
            "X-Rewrite-URL": "/admin",
            "Accept-Language": "es",
            "Referer": "https://google.com",
            "X-Real-IP": "127.0.0.1",
            "X-Client-IP": "127.0.0.1",
            "X-Forwarded-Scheme": "https",
        }
    
    def _get_cache_buster(self):
        """Genera un parámetro único para evitar la caché"""
        return f"?cb={hashlib.md5(str(time.time()).encode()).hexdigest()}"
    
    def _get_content_hash(self, url, headers=None):
        """Obtiene el hash MD5 del contenido de una URL"""
        try:
            response = self.session.get(url, headers=headers or {}, timeout=self.timeout)
            if response.status_code != 200:
                if self.verbose:
                    print(f"    ⚠️  Status code: {response.status_code}")
                return None, response.status_code, response.headers
            return hashlib.md5(response.content).hexdigest(), response.status_code, response.headers
        except requests.exceptions.Timeout:
            if self.verbose:
                print(f"    ⏰ Timeout")
            return None, None, None
        except requests.exceptions.ConnectionError:
            if self.verbose:
                print(f"    🔌 Error de conexión")
            return None, None, None
        except Exception as e:
            if self.verbose:
                print(f"    ❌ Error: {e}")
            return None, None, None
    
    def _compare_content(self, baseline_content, test_content):
        """Compara dos contenidos y devuelve las diferencias"""
        if not baseline_content or not test_content:
            return None
        
        baseline_lines = baseline_content.splitlines()
        test_lines = test_content.splitlines()
        
        diff_lines = []
        max_lines = min(len(baseline_lines), len(test_lines))
        
        for i in range(max_lines):
            if baseline_lines[i] != test_lines[i]:
                diff_lines.append({
                    'line': i + 1,
                    'baseline': baseline_lines[i][:200] + '...' if len(baseline_lines[i]) > 200 else baseline_lines[i],
                    'test': test_lines[i][:200] + '...' if len(test_lines[i]) > 200 else test_lines[i]
                })
                if len(diff_lines) >= 10:  # Limitamos a 10 diferencias
                    break
        
        if len(baseline_lines) != len(test_lines):
            diff_lines.append({
                'line': 'N/A',
                'baseline': f'Líneas: {len(baseline_lines)}',
                'test': f'Líneas: {len(test_lines)}'
            })
        
        return diff_lines
    
    def analyze_url(self, url, headers_to_test=None):
        """
        Analiza una URL probando todos los encabezados configurados
        
        Returns:
            dict: Resultados del análisis
        """
        if headers_to_test is None:
            headers_to_test = self.default_headers
        
        result = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'baseline': {},
            'tests': [],
            'vulnerable_headers': [],
            'summary': {
                'total_tested': 0,
                'changed': 0,
                'unchanged': 0,
                'errors': 0
            }
        }
        
        if self.verbose:
            print(f"\n🔍 Analizando: {url}")
        
        # 1. Obtener baseline (con cache buster)
        cb = self._get_cache_buster()
        test_url = url + cb
        baseline_hash, baseline_status, baseline_headers = self._get_content_hash(test_url)
        
        if not baseline_hash:
            if self.verbose:
                print(f"  ❌ No se pudo obtener baseline")
            result['summary']['errors'] += 1
            result['baseline'] = {'error': 'No se pudo obtener baseline'}
            return result
        
        if self.verbose:
            print(f"  ✅ Baseline obtenida: {baseline_hash[:16]}... (status: {baseline_status})")
        
        # Obtener contenido completo para diff
        baseline_content = None
        try:
            baseline_content = self.session.get(test_url, timeout=self.timeout).text
        except:
            pass
        
        result['baseline'] = {
            'hash': baseline_hash,
            'status_code': baseline_status,
            'headers': dict(baseline_headers)
        }
        
        # 2. Probar cada encabezado
        for header, value in headers_to_test.items():
            test_result = {
                'header': header,
                'value': value,
                'status': 'unchanged',
                'details': {}
            }
            
            if self.verbose:
                print(f"\n  🧪 Probando: {header} = {value}")
            
            # Petición con el encabezado (con cache buster)
            test_hash, test_status, test_headers = self._get_content_hash(test_url, headers={header: value})
            
            if not test_hash:
                test_result['status'] = 'error'
                test_result['details'] = {'error': 'No se pudo obtener respuesta'}
                result['summary']['errors'] += 1
                result['tests'].append(test_result)
                continue
            
            test_result['details']['hash'] = test_hash
            test_result['details']['status_code'] = test_status
            result['summary']['total_tested'] += 1
            
            # Verificar si el contenido cambió
            if test_hash != baseline_hash:
                if self.verbose:
                    print(f"    🔄 Contenido cambió (hash: {test_hash[:16]}...)")
                
                # Obtener contenido completo para diff
                test_content = None
                try:
                    test_content = self.session.get(test_url, headers={header: value}, timeout=self.timeout).text
                except:
                    pass
                
                # Verificar si el encabezado es UNKEYED
                # Petición SIN cache buster pero CON el encabezado
                cached_hash, cached_status, cached_headers = self._get_content_hash(url, headers={header: value})
                
                is_unkeyed = False
                if cached_hash and cached_hash == baseline_hash:
                    is_unkeyed = True
                    if self.verbose:
                        print(f"    ⚠️  ¡UNKEYED! {header} no es considerado en la caché")
                else:
                    if self.verbose:
                        print(f"    ✅ KEYED: {header} SÍ es considerado en la caché")
                
                # Calcular diferencias
                differences = None
                if baseline_content and test_content:
                    differences = self._compare_content(baseline_content, test_content)
                
                test_result['status'] = 'changed'
                test_result['details']['is_unkeyed'] = is_unkeyed
                test_result['details']['cached_hash'] = cached_hash
                test_result['details']['cached_status'] = cached_status
                test_result['details']['differences'] = differences
                test_result['details']['diff_count'] = len(differences) if differences else 0
                
                if is_unkeyed:
                    result['vulnerable_headers'].append(header)
                
                result['summary']['changed'] += 1
            else:
                if self.verbose:
                    print(f"    ✅ Sin cambio en el contenido")
                test_result['status'] = 'unchanged'
                result['summary']['unchanged'] += 1
            
            # Verificar si el encabezado se refleja en el contenido
            if baseline_content and test_result['status'] == 'changed':
                try:
                    test_full = self.session.get(test_url, headers={header: value}, timeout=self.timeout).text
                    if value in test_full:
                        test_result['details']['reflected'] = True
                        if self.verbose:
                            print(f"    📌 El valor '{value}' se refleja en el contenido")
                except:
                    pass
            
            result['tests'].append(test_result)
        
        return result
    
    def process_urls(self, urls, headers_to_test=None, max_workers=5):
        """
        Procesa una lista de URLs en paralelo
        
        Args:
            urls: Lista de URLs a analizar
            headers_to_test: Diccionario de encabezados a probar
            max_workers: Número de workers concurrentes
        """
        if headers_to_test is None:
            headers_to_test = self.default_headers
        
        total = len(urls)
        print(f"\n📊 Procesando {total} URLs con {max_workers} workers...")
        
        results = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_url = {
                executor.submit(self.analyze_url, url, headers_to_test): url 
                for url in urls
            }
            
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    result = future.result()
                    results.append(result)
                    print(f"\n✅ [{len(results)}/{total}] Completado: {url}")
                except Exception as e:
                    print(f"\n❌ [{len(results)}/{total}] Error en {url}: {e}")
                    results.append({
                        'url': url,
                        'error': str(e),
                        'vulnerable_headers': []
                    })
        
        self.results = results
        return results
    
    def load_urls_from_file(self, filename):
        """Carga URLs desde un archivo de texto"""
        try:
            with open(filename, 'r') as f:
                urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            return urls
        except FileNotFoundError:
            print(f"❌ Error: No se encontró el archivo '{filename}'")
            return []
    
    def generate_report(self, output_file=None):
        """Genera un reporte detallado en JSON y TXT"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if not output_file:
            output_file = f"cache_poisoning_report_{timestamp}"
        
        # Filtrar resultados
        vulnerable_urls = []
        for r in self.results:
            if r.get('vulnerable_headers'):
                vulnerable_urls.append(r)
        
        # Generar resumen
        summary = {
            'timestamp': timestamp,
            'total_urls': len(self.results),
            'vulnerable_urls': len(vulnerable_urls),
            'safe_urls': len(self.results) - len(vulnerable_urls),
            'headers_tested': list(self.default_headers.keys()),
            'vulnerable_details': []
        }
        
        for v in vulnerable_urls:
            summary['vulnerable_details'].append({
                'url': v['url'],
                'vulnerable_headers': v['vulnerable_headers']
            })
        
        # Guardar JSON
        json_file = f"{output_file}.json"
        with open(json_file, 'w') as f:
            json.dump({
                'summary': summary,
                'results': self.results
            }, f, indent=2)
        
        # Guardar TXT legible
        txt_file = f"{output_file}.txt"
        with open(txt_file, 'w') as f:
            f.write("="*70 + "\n")
            f.write("🔒 REPORTE DE VALIDACIÓN DE WEB CACHE POISONING\n")
            f.write("="*70 + "\n\n")
            
            f.write(f"📅 Fecha: {timestamp}\n")
            f.write(f"📊 Total URLs analizadas: {summary['total_urls']}\n")
            f.write(f"🔴 URLs con posibles vulnerabilidades: {summary['vulnerable_urls']}\n")
            f.write(f"🟢 URLs seguras: {summary['safe_urls']}\n")
            f.write(f"🧪 Encabezados probados: {', '.join(summary['headers_tested'])}\n\n")
            
            f.write("-"*70 + "\n")
            f.write("📋 URLs VULNERABLES (encabezados UNKEYED que cambian el contenido)\n")
            f.write("-"*70 + "\n\n")
            
            if vulnerable_urls:
                for v in vulnerable_urls:
                    f.write(f"🔴 {v['url']}\n")
                    for header in v['vulnerable_headers']:
                        # Encontrar el test correspondiente
                        for test in v['tests']:
                            if test['header'] == header and test['status'] == 'changed':
                                f.write(f"  ├─ {header}: {test['value']}\n")
                                if test['details'].get('differences'):
                                    f.write(f"  │  └─ {test['details']['diff_count']} diferencias encontradas\n")
                                break
                    f.write("\n")
            else:
                f.write("✅ No se encontraron URLs vulnerables.\n\n")
            
            f.write("-"*70 + "\n")
            f.write("📋 DETALLES POR URL\n")
            f.write("-"*70 + "\n\n")
            
            for r in self.results:
                f.write(f"📌 {r['url']}\n")
                if r.get('error'):
                    f.write(f"  ❌ Error: {r['error']}\n")
                else:
                    f.write(f"  Baseline hash: {r.get('baseline', {}).get('hash', 'N/A')[:16]}...\n")
                    for test in r.get('tests', []):
                        if test['status'] == 'changed':
                            status_icon = "🟡"
                            if test['details'].get('is_unkeyed'):
                                status_icon = "🔴"
                            f.write(f"  {status_icon} {test['header']}: {test['value']}\n")
                            if test['details'].get('diff_count', 0) > 0:
                                f.write(f"       {test['details']['diff_count']} líneas diferentes\n")
                        else:
                            f.write(f"  ✅ {test['header']}: Sin cambios\n")
                f.write("\n")
        
        print(f"\n📁 Reportes generados:")
        print(f"  - {json_file}")
        print(f"  - {txt_file}")
        
        return {
            'json': json_file,
            'txt': txt_file,
            'summary': summary
        }

def main():
    parser = argparse.ArgumentParser(
        description='🔒 Herramienta de validación de Web Cache Poisoning',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EJEMPLOS DE USO:
  # Procesar un archivo con URLs
  python cache_poisoning_validator.py -f urls.txt
  
  # Procesar una URL individual
  python cache_poisoning_validator.py -u https://ejemplo.com
  
  # Procesar con más workers y timeout personalizado
  python cache_poisoning_validator.py -f urls.txt -w 10 -t 15
  
  # Guardar resultados con nombre personalizado
  python cache_poisoning_validator.py -f urls.txt -o mis_resultados
        """
    )
    
    parser.add_argument('-f', '--file', help='Archivo con URLs (una por línea)')
    parser.add_argument('-u', '--url', help='URL individual a analizar')
    parser.add_argument('-o', '--output', help='Nombre base para los archivos de salida')
    parser.add_argument('-w', '--workers', type=int, default=5, help='Número de workers concurrentes (default: 5)')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Timeout en segundos (default: 10)')
    parser.add_argument('-q', '--quiet', action='store_true', help='Modo silencioso (menos output)')
    parser.add_argument('--headers', help='Archivo JSON con encabezados personalizados')
    
    args = parser.parse_args()
    
    # Validar argumentos
    if not args.file and not args.url:
        print("❌ Error: Debes especificar -f (archivo) o -u (URL)")
        parser.print_help()
        sys.exit(1)
    
    # Crear validador
    validator = CachePoisoningValidator(
        verbose=not args.quiet,
        timeout=args.timeout
    )
    
    # Cargar headers personalizados si se especifica
    headers_to_test = None
    if args.headers:
        try:
            with open(args.headers, 'r') as f:
                headers_to_test = json.load(f)
            print(f"📋 Headers personalizados cargados: {len(headers_to_test)} encabezados")
        except Exception as e:
            print(f"❌ Error al cargar headers: {e}")
            sys.exit(1)
    
    # Procesar URLs
    if args.url:
        # URL individual
        print(f"🔍 Analizando URL individual: {args.url}")
        result = validator.analyze_url(args.url, headers_to_test)
        validator.results = [result]
    else:
        # Archivo con URLs
        urls = validator.load_urls_from_file(args.file)
        if not urls:
            print("❌ No se encontraron URLs en el archivo")
            sys.exit(1)
        
        print(f"📂 Cargadas {len(urls)} URLs desde: {args.file}")
        validator.process_urls(urls, headers_to_test, args.workers)
    
    # Generar reporte
    output_name = args.output or "cache_poisoning_report"
    report = validator.generate_report(output_name)
    
    # Mostrar resumen en consola
    print("\n" + "="*70)
    print("📊 RESUMEN FINAL")
    print("="*70)
    print(f"Total URLs: {report['summary']['total_urls']}")
    print(f"🔴 Vulnerables: {report['summary']['vulnerable_urls']}")
    print(f"🟢 Seguras: {report['summary']['safe_urls']}")
    
    if report['summary']['vulnerable_urls'] > 0:
        print("\n⚠️  URLs con posibles vulnerabilidades:")
        for v in report['summary']['vulnerable_details']:
            print(f"  - {v['url']}")
            for h in v['vulnerable_headers']:
                print(f"    → {h}")
    
    print("\n✅ Proceso completado!")

if __name__ == "__main__":
    main()
