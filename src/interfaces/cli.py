"""Interface de linha de comando (CLI) para o scanner."""

import argparse
import sys
import json
from pathlib import Path
from typing import Optional

from src.domain import Target
from src.domain.exceptions import DomainException
from src.application import ScanEngine
from src.infrastructure import HttpClient, get_default_logger


class CLI:
    
    def __init__(self):
        self.parser = self._create_parser()
        self.use_colors = True
    
    def _create_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            prog='API Security Scanner',
            description='Scanner de segurança para APIs REST',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog='''
Exemplos de uso:
  python main.py scan https://api.exemplo.com
  python main.py scan https://api.exemplo.com --timeout 600 --output resultado.json
  python main.py list-modules
            '''
        )
        
        subparsers = parser.add_subparsers(dest='command', help='Comandos disponíveis')
        
        scan_parser = subparsers.add_parser('scan', help='Executar scan em uma URL')
        scan_parser.add_argument('url', type=str, help='URL do target (ex: https://api.exemplo.com)')
        scan_parser.add_argument('--timeout', type=int, default=300, help='Timeout global em segundos (padrão: 300)')
        scan_parser.add_argument('--module-timeout', type=int, default=30, help='Timeout por módulo em segundos (padrão: 30)')
        scan_parser.add_argument('--output', type=str, help='Arquivo de saída para resultado (JSON ou TXT)')
        scan_parser.add_argument('--no-color', action='store_true', help='Desabilitar cores no output')
        scan_parser.add_argument('--verbose', action='store_true', help='Modo verbose (logs detalhados)')
        
        list_parser = subparsers.add_parser('list-modules', help='Listar módulos disponíveis')
        
        return parser
    
    def run(self, args=None):
        parsed_args = self.parser.parse_args(args)
        
        if not parsed_args.command:
            self.parser.print_help()
            sys.exit(0)
        
        if parsed_args.command == 'scan':
            self._handle_scan(parsed_args)
        
        elif parsed_args.command == 'list-modules':
            self._handle_list_modules()
    
    def _handle_scan(self, args):
        self.use_colors = not args.no_color
        
        self._print_banner()
        
        try:
            target = Target(args.url)
            
            self._print_info(f"🎯 Target: {target.normalized_url}")
            self._print_info(f"🔒 Secure: {'Sim (HTTPS)' if target.is_secure else 'Não (HTTP)'}")
            print()
            
            http_client = HttpClient(
                default_timeout=10,
                verify_ssl=True,
                user_agent='API-Security-Scanner/1.0'
            )

            logger = get_default_logger()  
            
            engine = ScanEngine(
                http_client=http_client,
                global_timeout=args.timeout,
                module_timeout=args.module_timeout,
                max_workers=5,
                logger=logger
            )
            
            modules_count = engine.load_modules()
            
            if modules_count == 0:
                self._print_error("❌ Nenhum módulo encontrado!")
                self._print_info("💡 Crie módulos em src/modules/ seguindo o padrão SecurityModuleProtocol")
                sys.exit(1)
            
            result = engine.execute_scan(target)
            
            self._print_results(result)
            
            if args.output:
                self._save_results(result, args.output)
            
            sys.exit(0 if result.score >= 50 else 1)
        
        except DomainException as e:
            self._print_error(f"❌ Erro de validação: {e.message}")
            sys.exit(1)
        
        except Exception as e:
            self._print_error(f"❌ Erro inesperado: {str(e)}")
            if args.verbose:
                import traceback
                traceback.print_exc()
            sys.exit(1)
    
    def _handle_list_modules(self):
        self._print_banner()
        
        try:
            http_client = HttpClient()
            engine = ScanEngine(http_client=http_client)
            
            modules_count = engine.load_modules()
            
            if modules_count == 0:
                self._print_warning("⚠️  Nenhum módulo encontrado")
                return
            
            info = engine.get_loaded_modules_info()
            
            print(f"\n📦 Total de módulos: {info['total']}")
            print(f"✅ Ativos: {info['enabled']}")
            print(f"❌ Desabilitados: {info['disabled']}\n")
            
            print("─" * 80)
            print(f"{'STATUS':<8} {'NOME':<25} {'CATEGORIA':<15} {'PRIORIDADE':<10}")
            print("─" * 80)
            
            for module in info['modules']:
                status = "✓" if module['enabled'] else "✗"
                status_colored = self._color_text(status, 'green' if module['enabled'] else 'red')
                
                print(f"{status_colored:<8} {module['name']:<25} {module['category']:<15} {module['priority']:<10}")
                print(f"         {module['description']}")
                print()
            
            print("─" * 80)
        
        except Exception as e:
            self._print_error(f"❌ Erro ao listar módulos: {str(e)}")
            sys.exit(1)
    
    def _print_banner(self):
        banner = """
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║             🔐 API SECURITY SCANNER v1.0                      ║
║                                                               ║
║         Scanner de Segurança para APIs REST                   ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
        """
        print(self._color_text(banner, 'cyan'))
    
    def _print_results(self, result):
        print("\n" + "═" * 80)
        print(self._color_text("📊 RESULTADO DO SCAN", 'cyan', bold=True))
        print("═" * 80 + "\n")
        
        risk_color = self._get_risk_color(result.risk_level)
        
        print(f"🎯 Target: {result.target_url}")
        print(f"⏱️  Duração: {result.get_execution_time_formatted()}")
        print(f"📊 Score: {self._color_text(str(result.score) + '/100', risk_color, bold=True)}")
        print(f"⚠️  Nível de Risco: {self._color_text(result.risk_level, risk_color, bold=True)} - {result.get_risk_description()}")
        print()
        
        print("─" * 80)
        print(self._color_text("🔍 VULNERABILIDADES ENCONTRADAS", 'yellow', bold=True))
        print("─" * 80)
        print()
        
        total = result.total_vulnerabilities
        critical = result.get_critical_count()
        high = result.get_high_count()
        medium = result.get_medium_count()
        low = result.get_low_count()
        
        print(f"Total: {total}")
        
        if critical > 0:
            print(f"  {self._color_text('🔴 Críticas:', 'red', bold=True)} {critical}")
        
        if high > 0:
            print(f"  {self._color_text('🟠 Altas:', 'yellow', bold=True)} {high}")
        
        if medium > 0:
            print(f"  {self._color_text('🟡 Médias:', 'blue', bold=True)} {medium}")
        
        if low > 0:
            print(f"  {self._color_text('🟢 Baixas:', 'green', bold=True)} {low}")
        
        if total == 0:
            print(self._color_text("\n✅ Nenhuma vulnerabilidade encontrada!", 'green', bold=True))
        
        print("\n" + "═" * 80 + "\n")
    
    def _save_results(self, result, output_path: str):
        path = Path(output_path)
        
        try:
            if path.suffix.lower() == '.json':
                with open(path, 'w', encoding='utf-8') as f:
                    json.dump(result.to_dict(), f, indent=2, ensure_ascii=False)
                
                self._print_success(f"✅ Resultado salvo em: {path}")
            
            else:
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(str(result))
                
                self._print_success(f"✅ Resultado salvo em: {path}")
        
        except Exception as e:
            self._print_error(f"❌ Erro ao salvar arquivo: {str(e)}")
    
    def _get_risk_color(self, risk_level: str) -> str:
        colors = {
            'A': 'green',
            'B': 'blue',
            'C': 'yellow',
            'D': 'red'
        }
        return colors.get(risk_level, 'white')
    
    def _color_text(self, text: str, color: str, bold: bool = False) -> str:
        if not self.use_colors:
            return text
        
        colors = {
            'red': '\033[91m',
            'green': '\033[92m',
            'yellow': '\033[93m',
            'blue': '\033[94m',
            'cyan': '\033[96m',
            'white': '\033[97m',
        }
        
        bold_code = '\033[1m' if bold else ''
        reset = '\033[0m'
        
        color_code = colors.get(color, '')
        
        return f"{bold_code}{color_code}{text}{reset}"
    
    def _print_info(self, message: str):
        print(self._color_text(message, 'blue'))
    
    def _print_success(self, message: str):
        print(self._color_text(message, 'green'))
    
    def _print_warning(self, message: str):
        print(self._color_text(message, 'yellow'))
    
    def _print_error(self, message: str):
        print(self._color_text(message, 'red', bold=True))


def main():
    cli = CLI()
    cli.run()


if __name__ == '__main__':
    main()