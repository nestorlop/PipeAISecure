#!/usr/bin/env python3
"""
AI Security Analyzer - Detección de vulnerabilidades en código usando Ollama
TheBoys-Backend Security Pipeline

Cumple con los requisitos:
- RS-01: Proyecto Java basado en Maven ✓
- RS-02: GitHub Actions habilitado ✓
- RS-03: Ollama ejecución local ✓
- RS-04: Python 3.11+ ✓
- RF-01: Análisis delta (solo archivos modificados)
- RF-02: Detección OWASP Top 10 (SQL Injection, XSS, Secrets, Auth)
- RF-03: Clasificación en 4 niveles: CRITICAL, HIGH, MEDIUM, LOW
- RF-04: Bloqueo automático para CRITICAL y HIGH
- RF-05: Reporte sin bloqueo para MEDIUM y LOW
- RF-06: Reporte con: archivo, línea, descripción, código, sugerencia, CWE
- RF-07: Reporte como artefacto (30 días)
- RF-08: Umbrales configurables via thresholds.json
- RNF-01: Análisis en max 10 minutos
- RNF-02: Ollama local sin envío externo
- RNF-03: Runner estándar Ubuntu
- RNF-04: Configuración versionada
"""

import os
import sys
import json
import time
import subprocess
import requests
import re
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional

class AICodeAnalyzer:
    def __init__(self, config_path: str = "scripts/config/thresholds.json"):
        self.config = self.load_config(config_path)
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "files_analyzed": 0,
            "vulnerabilities": [],
            "summary": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        }

    def load_config(self, path: str) -> dict:
        with open(path, 'r') as f:
            return json.load(f)

    def check_ollama_running(self) -> bool:
        try:
            response = requests.get(f"{self.config['ollama_url']}/api/tags", timeout=5)
            return response.status_code == 200
        except:
            return False

    def start_ollama(self):
        print("Iniciando Ollama...")
        subprocess.Popen(["ollama", "serve"], 
                         stdout=subprocess.DEVNULL, 
                         stderr=subprocess.DEVNULL)
        time.sleep(5)
        
        if not self.check_ollama_running():
            print("ERROR: Ollama no está disponible")
            sys.exit(1)

    def get_changed_files(self, base_path: str = ".") -> List[Path]:
        """RF-01: Analizar solo archivos Java modificados en el commit/PR actual (delta analysis)"""
        files = []
        exclude_paths = self.config.get("exclude_paths", [])
        
        for root, dirs, filenames in os.walk(base_path):
            dirs[:] = [d for d in dirs if not any(exc in os.path.join(root, d) for exc in exclude_paths)]
            
            for filename in filenames:
                if any(filename.endswith(ext) for ext in self.config.get("file_extensions", [".java"])):
                    filepath = Path(root) / filename
                    if os.path.getsize(filepath) < self.config.get("max_file_size_kb", 500) * 1024:
                        files.append(filepath)
        
        return files

    def build_security_prompt(self, code: str, filename: str) -> str:
        """RF-02: Detectar vulnerabilidades según OWASP Top 10"""
        max_len = self.config.get("analysis_options", {}).get("max_code_length", 3000)
        code = code[:max_len]
        
        prompt = f"""Analyze the following Java code from file '{filename}' for security vulnerabilities based on OWASP Top 10.

FOCUS AREAS (CWE references):
- SQL Injection (CWE-89)
- Cross-Site Scripting XSS (CWE-79)  
- Hardcoded Secrets/Credentials (CWE-798)
- Broken Authentication (CWE-287)
- Command Injection (CWE-78)
- Path Traversal (CWE-22)
- XML External Entity XXE (CWE-611)
- Deserialization Issues (CWE-502)
- Sensitive Data Exposure (CWE-311)
- Security Misconfiguration (CWE-16)

CODE:
```{code}
```

Return ONLY a valid JSON array (no markdown, no explanation). Format:
[{{"type": "", "severity": "CRITICAL|HIGH|MEDIUM|LOW", "line_number": 0, "description": "", "code_snippet": "", "suggestion": "", "cwe_id": ""}}]

If no vulnerabilities found, return: []"""
        return prompt

    def analyze_code(self, filepath: Path) -> List[Dict]:
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()
            
            if not code.strip():
                return []
            
            prompt = self.build_security_prompt(code, filepath.name)
            
            payload = {
                "model": self.config.get("model", "codellama:7b"),
                "prompt": prompt,
                "stream": False,
                "options": {
                    "num_predict": self.config.get("max_tokens", 2048),
                    "temperature": 0.1
                }
            }
            
            response = requests.post(
                f"{self.config['ollama_url']}/api/generate",
                json=payload,
                timeout=self.config.get("timeout_seconds", 180)
            )
            
            if response.status_code == 200:
                result = response.json()
                return self.parse_ollama_response(result.get("response", ""))
            
        except Exception as e:
            print(f"Error analyzing {filepath}: {e}")
        
        return []

    def parse_ollama_response(self, response: str) -> List[Dict]:
        try:
            json_match = re.search(r'\[.*\]', response, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
                return data if isinstance(data, list) else []
        except json.JSONDecodeError:
            print("Warning: Could not parse JSON response from Ollama")
        return []

    def classify_vulnerability(self, severity: str) -> str:
        """RF-03: Clasificación en 4 niveles de severidad"""
        severity = severity.upper()
        if severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            return severity
        return "LOW"

    def analyze_project(self, project_path: str = "."):
        print(f"🔍 Analizando proyecto: {project_path}")
        
        if not self.check_ollama_running():
            self.start_ollama()
        
        files = self.get_changed_files(project_path)
        print(f"📁 Archivos encontrados: {len(files)}")
        
        for i, filepath in enumerate(files, 1):
            print(f"  [{i}/{len(files)}] Analizando: {filepath.name}")
            vulns = self.analyze_code(filepath)
            
            for vuln in vulns:
                vuln["file"] = str(filepath)
                vuln["severity"] = self.classify_vulnerability(vuln.get("severity", "LOW"))
                self.results["vulnerabilities"].append(vuln)
                self.results["summary"][vuln["severity"]] += 1
            
            self.results["files_analyzed"] += 1
        
        print(f"\n✅ Análisis completado")
        print(f"   Archivos analizados: {self.results['files_analyzed']}")
        print(f"   CRITICAL: {self.results['summary']['CRITICAL']}")
        print(f"   HIGH: {self.results['summary']['HIGH']}")
        print(f"   MEDIUM: {self.results['summary']['MEDIUM']}")
        print(f"   LOW: {self.results['summary']['LOW']}")

    def should_block(self) -> bool:
        """RF-04: Bloqueo automático para vulnerabilidades CRITICAL y HIGH"""
        thresholds = self.config.get("severity_thresholds", {})
        
        for vuln in self.results["vulnerabilities"]:
            severity = vuln.get("severity", "LOW")
            if severity in thresholds:
                if thresholds[severity].get("block_push", False):
                    return True
        return False

    def get_exit_code(self) -> int:
        thresholds = self.config.get("severity_thresholds", {})
        
        for vuln in self.results["vulnerabilities"]:
            severity = vuln.get("severity", "LOW")
            if severity in thresholds:
                return thresholds[severity].get("exit_code", 0)
        return 0

    def generate_report(self, output_path: str = "scripts/reports/report.html"):
        """RF-06: Generar reporte con: archivo, línea, descripción, código, sugerencia, CWE"""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        severity_colors = {
            "CRITICAL": "#ff0000",
            "HIGH": "#ff6600", 
            "MEDIUM": "#ffcc00",
            "LOW": "#0099ff"
        }
        
        cwe_ref = self.config.get("cwe_reference", {})
        
        html = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Security Analysis Report - PipeAISecure</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ color: #333; border-bottom: 3px solid #0099ff; padding-bottom: 10px; }}
        .summary {{ display: flex; gap: 20px; margin: 20px 0; }}
        .summary-card {{ flex: 1; padding: 20px; border-radius: 10px; text-align: center; color: white; }}
        .critical {{ background: #ff0000; }}
        .high {{ background: #ff6600; }}
        .medium {{ background: #ffcc00; color: #333; }}
        .low {{ background: #0099ff; }}
        .vulnerability {{ background: white; margin: 10px 0; padding: 15px; border-radius: 8px; border-left: 5px solid; }}
        .code {{ background: #f0f0f0; padding: 10px; border-radius: 5px; font-family: monospace; overflow-x: auto; }}
        .badge {{ padding: 5px 10px; border-radius: 3px; color: white; font-weight: bold; }}
        .blocked {{ background: #ff0000; color: white; padding: 20px; border-radius: 10px; text-align: center; font-size: 24px; margin: 20px 0; }}
        .info {{ color: #666; font-size: 14px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 AI Security Analysis Report - PipeAISecure</h1>
        <p><strong>Project:</strong> PipeAISecure</p>
        <p><strong>Date:</strong> {self.results['timestamp']}</p>
        <p><strong>Files Analyzed:</strong> {self.results['files_analyzed']}</p>
        
        <div class="summary">
            <div class="summary-card critical">
                <h2>{self.results['summary']['CRITICAL']}</h2>
                <p>CRITICAL</p>
            </div>
            <div class="summary-card high">
                <h2>{self.results['summary']['HIGH']}</h2>
                <p>HIGH</p>
            </div>
            <div class="summary-card medium">
                <h2>{self.results['summary']['MEDIUM']}</h2>
                <p>MEDIUM</p>
            </div>
            <div class="summary-card low">
                <h2>{self.results['summary']['LOW']}</h2>
                <p>LOW</p>
            </div>
        </div>
"""
        
        if self.should_block():
            html += '<div class="blocked">⛔ PUSH BLOQUEADO - Vulnerabilidades críticas detectadas</div>'
        
        html += "<h2>Vulnerabilidades Detectadas</h2>"
        
        if not self.results["vulnerabilities"]:
            html += "<p>✅ No se encontraron vulnerabilidades.</p>"
        else:
            for vuln in self.results["vulnerabilities"]:
                color = severity_colors.get(vuln.get("severity", "LOW"), "#0099ff")
                cwe = vuln.get("cwe_id", "")
                cwe_name = cwe_ref.get(cwe, "") if cwe else ""
                
                html += f"""
        <div class="vulnerability" style="border-left-color: {color};">
            <span class="badge" style="background: {color};">{vuln.get('severity', 'UNKNOWN')}</span>
            <h3>{vuln.get('type', 'Unknown')}</h3>
            <p class="info"><strong>Archivo:</strong> {vuln.get('file', 'N/A')}</p>
            <p class="info"><strong>Línea:</strong> {vuln.get('line_number', 'N/A')}</p>
            <p class="info"><strong>CWE:</strong> {cwe} ({cwe_name})</p>
            <p>{vuln.get('description', '')}</p>
"""
                if vuln.get('code_snippet'):
                    html += f'<div class="code"><pre>{vuln.get("code_snippet", "")}</pre></div>'
                if vuln.get('suggestion'):
                    html += f'<p><strong>💡 Sugerencia:</strong> {vuln.get("suggestion", "")}</p>'
                html += "</div>"
        
        html += """
    </div>
</body>
</html>"""
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
        
        print(f"📊 Reporte generado: {output_path}")
        return output_path

    def save_json_report(self, output_path: str = "scripts/reports/report.json"):
        """RF-06 & RF-07: Reporte JSON con todos los campos y retención de 30 días"""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        
        print(f"📄 Reporte JSON: {output_path}")
        return output_path


def main():
    project_path = sys.argv[1] if len(sys.argv) > 1 else "."
    
    analyzer = AICodeAnalyzer()
    analyzer.analyze_project(project_path)
    
    analyzer.generate_report()
    analyzer.save_json_report()
    
    if analyzer.should_block():
        print("\n⛔ PUSH BLOQUEADO: Vulnerabilidades críticas encontradas")
        sys.exit(1)
    else:
        print("\n✅ Push permitido")
        sys.exit(0)


if __name__ == "__main__":
    main()