"""桌面程序入口。"""
import sys

if __name__ == '__main__':
    try:
        from keyaudit.app import main
    except ImportError as exc:
        print('GUI 依赖尚未安装，请先运行：python -m pip install -r requirements-gui.txt', file=sys.stderr)
        raise SystemExit(1) from exc
    raise SystemExit(main())
