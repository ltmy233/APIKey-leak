"""界面配色和控件样式。"""
from PySide6.QtGui import QColor, QFont, QPalette


COLORS = {'background': '#101820', 'surface': '#17232E', 'raised': '#1D2C39',
          'border': '#334653', 'text': '#ECF2F6', 'muted': '#A7B6C4',
          'accent': '#73C9CF', 'warning': '#E4BC78', 'danger': '#F5A6A6'}


def apply_theme(app):
    app.setStyle('Fusion')
    app.setFont(QFont('Microsoft YaHei UI', 10))
    palette = QPalette()
    for role, color in ((QPalette.ColorRole.Window, COLORS['background']),
                        (QPalette.ColorRole.WindowText, COLORS['text']),
                        (QPalette.ColorRole.Base, COLORS['background']),
                        (QPalette.ColorRole.AlternateBase, COLORS['surface']),
                        (QPalette.ColorRole.Text, COLORS['text']),
                        (QPalette.ColorRole.Button, COLORS['raised']),
                        (QPalette.ColorRole.ButtonText, COLORS['text']),
                        (QPalette.ColorRole.Highlight, '#315A65'),
                        (QPalette.ColorRole.HighlightedText, COLORS['text'])):
        palette.setColor(role, QColor(color))
    app.setPalette(palette)
    app.setStyleSheet(STYLE)


STYLE = '''
QWidget { color: #ECF2F6; }
QMainWindow, QWidget#root { background: #101820; }
QFrame#sidebar { background: #121F29; border-right: 1px solid #334653; }
QFrame#card { background: #17232E; border: 1px solid #334653; border-radius: 8px; }
QLabel#brand { font: 700 20pt "Bahnschrift"; letter-spacing: 1px; }
QLabel#eyebrow { color: #73C9CF; font: 700 9pt "Cascadia Mono"; letter-spacing: 1px; }
QLabel#title { font-size: 19pt; font-weight: 700; }
QLabel#section { font-size: 11pt; font-weight: 700; }
QLabel#muted { color: #A7B6C4; }
QLabel#metric { color: #ECF2F6; font: 600 18pt "Bahnschrift"; }
QLabel#notice { background: #1B303A; border-left: 3px solid #73C9CF; padding: 12px; color: #C9E6E9; }
QLabel#error { color: #F5A6A6; background: #34262E; padding: 10px; border-radius: 5px; }
QPushButton { background: #243745; border: 1px solid #405665; border-radius: 5px; padding: 8px 14px; min-height: 22px; }
QPushButton:hover { background: #304B5C; border-color: #73C9CF; }
QPushButton:pressed { background: #182C37; }
QPushButton:focus, QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QListWidget:focus, QTableView:focus { border: 1px solid #A5EDF1; }
QPushButton:disabled { color: #718390; background: #1A2833; border-color: #2A3B48; }
QPushButton#primary { background: #73C9CF; color: #10252C; border-color: #73C9CF; font-weight: 700; }
QPushButton#primary:hover { background: #9ADDE1; }
QPushButton#primary:disabled { background: #294750; border-color: #294750; color: #8AADB2; }
QPushButton#danger { border-color: #89575F; color: #F5B7BC; }
QPushButton#nav { text-align: left; background: transparent; border: 0; padding: 12px; }
QPushButton#nav:checked { background: #233C49; color: #A5EDF1; border-left: 3px solid #73C9CF; border-radius: 0; }
QPushButton#link { background: transparent; border: 0; color: #9CDEE3; padding: 2px 6px; min-height: 18px; }
QLineEdit, QComboBox, QSpinBox { background: #101C26; border: 1px solid #405665; border-radius: 5px; padding: 8px; min-height: 22px; selection-background-color: #315A65; }
QLineEdit:disabled { color: #718390; }
QComboBox QAbstractItemView { background: #1D2C39; selection-background-color: #315A65; }
QListWidget { background: #101C26; border: 1px solid #334653; border-radius: 5px; padding: 4px; }
QListWidget::item { min-height: 29px; padding: 2px; }
QListWidget::item:selected { background: #294653; }
QCheckBox { spacing: 8px; }
QCheckBox::indicator, QListWidget::indicator { width: 16px; height: 16px; }
QTableView { background: #101C26; alternate-background-color: #15232E; border: 0; gridline-color: #2B3C49; selection-background-color: #294653; selection-color: #ECF2F6; }
QHeaderView::section { background: #1D2C39; color: #B8C7D2; border: 0; border-bottom: 1px solid #405665; padding: 10px 8px; text-align: left; }
QTableView::item { padding: 6px; border-bottom: 1px solid #233440; }
QPlainTextEdit { background: #101C26; color: #B7C9D4; border: 1px solid #334653; border-radius: 5px; padding: 10px; font: 9pt "Cascadia Mono"; }
QProgressBar { background: #263B48; border: 0; border-radius: 3px; min-height: 6px; max-height: 6px; }
QProgressBar::chunk { background: #73C9CF; border-radius: 3px; }
QScrollArea { background: transparent; border: 0; }
QScrollBar:vertical { background: #14212B; width: 10px; margin: 0; }
QScrollBar::handle:vertical { background: #48606E; min-height: 32px; border-radius: 4px; }
QScrollBar:horizontal { background: #14212B; height: 10px; }
QScrollBar::handle:horizontal { background: #48606E; min-width: 32px; border-radius: 4px; }
QScrollBar::add-line, QScrollBar::sub-line { width: 0; height: 0; }
QToolTip { background: #243745; color: #ECF2F6; border: 1px solid #73C9CF; padding: 8px; }
QSplitter::handle { background: #223440; }
'''
