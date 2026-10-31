"""目录遍历和文件筛选共用的排除项。"""
IGNORED_DIRS = frozenset({'.git', 'node_modules', '.venv', 'venv', '__pycache__',
                          'vendor', 'dist', 'build'})
