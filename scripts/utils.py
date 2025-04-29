import subprocess, logging

def run(cmd):
    logging.info(f"Ejecutando: {' '.join(cmd)}")
    return subprocess.run(cmd, check=True)
