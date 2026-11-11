import argparse
import json
import sys

from .analyzer import analyze, render_text
from .visita import ejecutar as visita


def main(argv=None):
    ap = argparse.ArgumentParser(prog="botnet_lab",
                                 description="Detección de dispositivos IoT comprometidos en redes reales")
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("analyze", help="analiza un .pcap o .pcapng")
    a.add_argument("captura")
    a.add_argument("--device", help="limitar a una IP local")
    a.add_argument("--local-net", action="append", help="red local CIDR (por defecto, rangos privados)")
    a.add_argument("--min-pps", type=int, default=200, help="umbral de inundación (200 pps)")
    a.add_argument("--min-secs", type=int, default=5, help="duración mínima en segundos (5)")
    a.add_argument("--json", action="store_true", help="salida JSON")

    v = sub.add_parser("visita", help="asistente para revisar un aparato en casa del cliente")
    v.add_argument("--interfaz", help="interfaz de captura (por defecto, se detecta el hotspot de Windows)")
    v.add_argument("--mac", help="MAC del aparato (captura solo su tráfico)")
    v.add_argument("--minutos", type=float, default=15, help="duración de la captura (15)")
    v.add_argument("--salida", default="informes", help="carpeta del informe (informes)")
    v.add_argument("--guardar", action="store_true", help="conservar la captura como evidencia")
    v.add_argument("--referencia", help="referencia del cliente/visita (opcional)")
    v.add_argument("--tecnico", help="nombre del técnico (opcional)")
    v.add_argument("--local-net", action="append", help="red local CIDR (por defecto, rangos privados)")
    v.add_argument("--sin-preguntas", action="store_true", help="no pedir datos por teclado")
    v.add_argument("--desde-captura", nargs="+", metavar="PCAP",
                   help="no capturar: generar el informe de capturas ya existentes")

    args = ap.parse_args(argv)
    if args.cmd == "visita":
        return visita(args)
    res = analyze(args.captura, min_pps=args.min_pps, min_secs=args.min_secs,
                  local_nets=args.local_net, device=args.device)
    print(json.dumps(res, indent=2, ensure_ascii=False) if args.json else render_text(res))
    return 2 if res["verdict"] == "sospechoso" else 0


if __name__ == "__main__":
    sys.exit(main())
