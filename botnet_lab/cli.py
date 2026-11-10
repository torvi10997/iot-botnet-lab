import argparse
import json
import sys

from .analyzer import analyze, render_text
from .emulator import generate


def main(argv=None):
    ap = argparse.ArgumentParser(prog="botnet_lab",
                                 description="Emulador y analizador de dispositivos IoT comprometidos")
    sub = ap.add_subparsers(dest="cmd", required=True)

    e = sub.add_parser("emulate", help="genera una captura sintética (no envía tráfico a la red)")
    e.add_argument("salida", help="archivo .pcap de salida")
    e.add_argument("--clean", action="store_true", help="dispositivo sano (para probar falsos positivos)")
    e.add_argument("--duration", type=int, default=120, help="segundos de captura (120)")
    e.add_argument("--pps", type=int, default=600, help="paquetes/s de cada inundación (600)")
    e.add_argument("--flood-secs", type=int, default=15, help="duración de cada inundación (15)")
    e.add_argument("--scan", action="store_true", help="añade un barrido SYN al puerto 22")
    e.add_argument("--seed", type=int, default=7)

    a = sub.add_parser("analyze", help="analiza un .pcap o .pcapng")
    a.add_argument("captura")
    a.add_argument("--device", help="limitar a una IP local")
    a.add_argument("--local-net", action="append", help="red local CIDR (por defecto, rangos privados)")
    a.add_argument("--min-pps", type=int, default=200, help="umbral de inundación (200 pps)")
    a.add_argument("--min-secs", type=int, default=5, help="duración mínima en segundos (5)")
    a.add_argument("--json", action="store_true", help="salida JSON")

    args = ap.parse_args(argv)
    if args.cmd == "emulate":
        n = generate(args.salida, infected=not args.clean, duration=args.duration,
                     flood_pps=args.pps, flood_secs=args.flood_secs, scan=args.scan, seed=args.seed)
        print("Escribí %d paquetes en %s" % (n, args.salida))
        return 0
    res = analyze(args.captura, min_pps=args.min_pps, min_secs=args.min_secs,
                  local_nets=args.local_net, device=args.device)
    print(json.dumps(res, indent=2, ensure_ascii=False) if args.json else render_text(res))
    return 2 if res["verdict"] == "sospechoso" else 0


if __name__ == "__main__":
    sys.exit(main())
