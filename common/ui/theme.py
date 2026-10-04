"""Shared visual themes for VPN Admin Panel companion applications."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

_ICON_DIRECTORY = Path(__file__).resolve().parent / "assets" / "icons"
_SPINBOX_UP_ICON = (_ICON_DIRECTORY / "chevron-up.svg").as_posix()
_SPINBOX_DOWN_ICON = (_ICON_DIRECTORY / "chevron-down.svg").as_posix()


@dataclass(frozen=True)
class ThemeColors:
    window_background: str = "#0B1624"
    panel_background: str = "#101D2B"
    panel_border: str = "#23374B"
    control_background: str = "#0B1724"
    control_border: str = "#31475D"
    text: str = "#E5EDF7"
    muted_text: str = "#9AAFC5"
    blue: str = "#16B5E8"
    blue_hover: str = "#35C4F2"
    blue_dark: str = "#152B3D"
    blue_dark_hover: str = "#1B3A52"
    amber: str = "#F0B43B"
    amber_hover: str = "#FFC85A"
    deploy_background: str = "#241A0B"
    deploy_border: str = "#A66A08"
    warning_background: str = "#211908"
    log_background: str = "#08131F"
    success: str = "#78DF69"
    error: str = "#FF8798"


@dataclass(frozen=True)
class ThemeDefinition:
    key: str
    display_name: str
    colors: ThemeColors


def make_theme(
    key: str,
    display_name: str,
    window: str,
    panel: str,
    border: str,
    control: str,
    text: str,
    muted_text: str,
    action: str,
    action_hover: str,
    action_dark: str,
    amber: str,
    amber_hover: str,
    *,
    control_border: str | None = None,
    action_dark_hover: str | None = None,
    deploy_background: str | None = None,
    deploy_border: str | None = None,
    warning_background: str | None = None,
    log_background: str | None = None,
    success: str | None = None,
    error: str | None = None,
) -> ThemeDefinition:
    """Build a complete palette with consistent derived-color defaults."""
    defaults = ThemeColors()
    return ThemeDefinition(
        key,
        display_name,
        ThemeColors(
            window_background=window,
            panel_background=panel,
            panel_border=border,
            control_background=control,
            control_border=control_border or border,
            text=text,
            muted_text=muted_text,
            blue=action,
            blue_hover=action_hover,
            blue_dark=action_dark,
            blue_dark_hover=action_dark_hover or action,
            amber=amber,
            amber_hover=amber_hover,
            deploy_background=deploy_background or panel,
            deploy_border=deploy_border or amber,
            warning_background=warning_background or panel,
            log_background=log_background or control,
            success=success or defaults.success,
            error=error or defaults.error,
        ),
    )


THEMES: dict[str, ThemeDefinition] = {
    theme.key: theme
    for theme in (
        make_theme(
            "dark_noc",
            "Dark NOC",
            "#0B1624",
            "#101D2B",
            "#23374B",
            "#0B1724",
            "#E5EDF7",
            "#9AAFC5",
            "#16B5E8",
            "#35C4F2",
            "#152B3D",
            "#F0B43B",
            "#FFC85A",
            control_border="#31475D",
            action_dark_hover="#1B3A52",
            deploy_background="#211B10",
            deploy_border="#8C681F",
            warning_background="#211B10",
            log_background="#08131F",
        ),
        make_theme(
            "midnight_blue",
            "Midnight Blue",
            "#06091A",
            "#101633",
            "#454CA1",
            "#090E24",
            "#F0F2FF",
            "#B7BCE5",
            "#5964E8",
            "#7A83FF",
            "#252D68",
            "#F4B942",
            "#FFD365",
            control_border="#555CB5",
            action_dark_hover="#343E89",
            deploy_background="#251D10",
            deploy_border="#C58D21",
            warning_background="#28200F",
            log_background="#050817",
            success="#76E5A2",
            error="#FF92B0",
        ),
        make_theme(
            "forest_ops",
            "Forest Ops",
            "#07130E",
            "#0C2118",
            "#2F7955",
            "#07170F",
            "#E6F7EC",
            "#AACFB9",
            "#2FB879",
            "#52D99A",
            "#123D2A",
            "#E9AC35",
            "#FFD16C",
            control_border="#3C8761",
            action_dark_hover="#1B563A",
            deploy_background="#29200D",
            deploy_border="#A97B20",
            warning_background="#2B210C",
            log_background="#030B06",
            success="#78E58D",
            error="#FF91A0",
        ),
        make_theme(
            "graphite",
            "Graphite",
            "#151719",
            "#202326",
            "#5C6670",
            "#171A1D",
            "#F1F3F5",
            "#B8C0C7",
            "#6397C9",
            "#80B3E5",
            "#2D4258",
            "#D6A13D",
            "#F1C35F",
            control_border="#6C7781",
            action_dark_hover="#3C566F",
            deploy_background="#2D2415",
            deploy_border="#9B7738",
            warning_background="#2D2617",
            log_background="#101214",
            success="#86D99B",
            error="#EF93A0",
        ),
        make_theme(
            "monokai_terminal",
            "Monokai Terminal",
            "#171A15",
            "#272822",
            "#75715E",
            "#1E1F1C",
            "#F8F8F2",
            "#B9B9A8",
            "#A6E22E",
            "#BEF15A",
            "#3E4A18",
            "#FD971F",
            "#FFB454",
        ),
        make_theme(
            "cyber_lime",
            "Cyber Lime",
            "#0B0E0A",
            "#161B14",
            "#6C9E38",
            "#10150D",
            "#EEFFD8",
            "#A9C58B",
            "#B6FF00",
            "#D1FF4C",
            "#354A12",
            "#F2B632",
            "#FFD45D",
        ),
        make_theme(
            "slate_blue",
            "Slate Blue",
            "#263545",
            "#33475B",
            "#70859C",
            "#2C3D50",
            "#E8F0F7",
            "#B4C3D1",
            "#5F93C7",
            "#82B2E2",
            "#3D5B78",
            "#D3A642",
            "#E8C05C",
        ),
        make_theme(
            "copper_forge",
            "Copper Forge",
            "#171311",
            "#29201C",
            "#8A6048",
            "#201916",
            "#F7ECE5",
            "#C7AFA0",
            "#B96D39",
            "#D98A50",
            "#4A2D1E",
            "#D5A13C",
            "#F0C65F",
        ),
        make_theme(
            "ink_gold",
            "Ink & Gold",
            "#0C0D0F",
            "#18191C",
            "#8D762C",
            "#111215",
            "#F4F0E2",
            "#BEB7A0",
            "#B79A39",
            "#D8BC5C",
            "#3A3219",
            "#E0B84E",
            "#F4D577",
        ),
        make_theme(
            "retro_crt",
            "Retro CRT",
            "#07110B",
            "#102016",
            "#4C8B5C",
            "#09160D",
            "#C5F5B6",
            "#83B77E",
            "#62C462",
            "#91E486",
            "#1F4D28",
            "#D5B34B",
            "#E8D377",
        ),
        make_theme(
            "tangerine_dark",
            "Tangerine Dark",
            "#171A1D",
            "#262B30",
            "#67727D",
            "#1E2226",
            "#F2F4F5",
            "#B7BEC5",
            "#E8792E",
            "#FA9A51",
            "#4C2B19",
            "#F0A13A",
            "#FFC366",
        ),
        make_theme(
            "plum_smoke",
            "Plum Smoke",
            "#2A222D",
            "#3A2D3E",
            "#826789",
            "#312635",
            "#F8EEF8",
            "#CFB9CF",
            "#B36B9A",
            "#D58AB8",
            "#57384F",
            "#D19B3D",
            "#EFC35D",
        ),
        make_theme(
            "steelworks",
            "Steelworks",
            "#20262A",
            "#30383D",
            "#77838C",
            "#262D31",
            "#EDF1F3",
            "#B8C1C7",
            "#8096A5",
            "#A6B8C3",
            "#48565F",
            "#E1B832",
            "#F5D15A",
        ),
        make_theme(
            "obsidian_teal",
            "Obsidian Teal",
            "#071415",
            "#102627",
            "#397E7F",
            "#0A1D1E",
            "#E3FAF8",
            "#A6CECB",
            "#12A9A5",
            "#38D0CA",
            "#164C4C",
            "#E0A63B",
            "#F4C55D",
        ),
        make_theme(
            "light_admin",
            "Light Admin",
            "#EDF3FA",
            "#FFFFFF",
            "#93ABC6",
            "#F8FBFF",
            "#10243D",
            "#526A86",
            "#087BC1",
            "#1396E5",
            "#E2EEF9",
            "#A65B00",
            "#C87505",
            control_border="#7E9AB8",
            action_dark_hover="#CBE3F7",
            deploy_background="#FFF7E8",
            deploy_border="#C17A13",
            warning_background="#FFF4D8",
            log_background="#F8FAFC",
            success="#238636",
            error="#C62845",
        ),
        make_theme(
            "warm_paper",
            "Warm Paper",
            "#F5EBDD",
            "#FFF9F0",
            "#B79F84",
            "#FFFDFC",
            "#3D3025",
            "#766452",
            "#B55239",
            "#D0694E",
            "#F0D7C5",
            "#8B5B2D",
            "#AA7440",
        ),
        make_theme(
            "desert_sand",
            "Desert Sand",
            "#EDE1C8",
            "#FFF8EA",
            "#B99A6D",
            "#FFFDF8",
            "#493622",
            "#806A4C",
            "#246D70",
            "#368C8D",
            "#D7EEE7",
            "#B97825",
            "#D6983B",
        ),
        make_theme(
            "ivory_ledger",
            "Ivory Ledger",
            "#F6F1E6",
            "#FFFCF5",
            "#8B9BB1",
            "#FFFFFF",
            "#1F3652",
            "#607692",
            "#255A9C",
            "#3E7BC2",
            "#DCE8F5",
            "#A6463D",
            "#C85B51",
        ),
        make_theme(
            "sepia_archive",
            "Sepia Archive",
            "#E8D8BD",
            "#F8EFDF",
            "#A47D55",
            "#FFF9EE",
            "#422C1B",
            "#76573B",
            "#865735",
            "#AA784F",
            "#EFDCC4",
            "#A97027",
            "#CA963F",
        ),
    )
}

DEFAULT_THEME_KEY = "dark_noc"
DARK_THEME = THEMES[DEFAULT_THEME_KEY].colors


def get_theme(key: str) -> ThemeDefinition:
    """Return a registered theme, falling back to the default."""
    return THEMES.get(key, THEMES[DEFAULT_THEME_KEY])


def available_themes() -> tuple[ThemeDefinition, ...]:
    """Return themes in their presentation order."""
    return tuple(THEMES.values())


_LIGHT_THEME_KEYS = frozenset(
    {"light_admin", "warm_paper", "desert_sand", "ivory_ledger", "sepia_archive"}
)


def is_light_theme(key: str) -> bool:
    """Return whether a registered theme belongs to the light-theme section."""
    return key in _LIGHT_THEME_KEYS


def build_stylesheet(colors: ThemeColors = DARK_THEME) -> str:
    """Build the Qt stylesheet from the named application palette."""
    return f"""
        QMainWindow, QDialog {{ background: {colors.window_background}; color: {colors.text}; }}
        QWidget {{ color: {colors.text}; font-size: 14px; }}
        QLabel#title {{ font-size: 25px; font-weight: 700; }}
        QLabel#subtitle {{ color: {colors.muted_text}; font-size: 13px; }}
        QGroupBox {{
            background: {colors.panel_background}; border: 1px solid {colors.panel_border};
            border-radius: 10px; margin-top: 14px; padding: 22px 16px 16px;
            font-size: 18px; font-weight: 600;
        }}
        QGroupBox::title {{ subcontrol-origin: margin; left: 14px; padding: 0 6px; }}
        QGroupBox#serverGroup, QGroupBox#operationLogGroup {{
            background: transparent; border: 0; border-radius: 0; margin-top: 0; padding: 0;
        }}
        QFrame#sectionDivider {{
            background: transparent; border: 0; min-height: 5px; max-height: 5px;
        }}
        QTabWidget#actionTabs {{ background: transparent; }}
        QTabWidget#actionTabs::pane {{
            background: {colors.panel_background}; border: 1px solid {colors.panel_border};
            border-radius: 0 10px 10px 10px; top: -1px;
        }}
        QWidget#actionTabPage {{ background: {colors.panel_background}; }}
        QTabBar::tab {{
            background: transparent; border: 0; border-bottom: 3px solid transparent;
            color: {colors.muted_text}; font-size: 15px; min-height: 38px;
            padding: 2px 16px; margin-right: 4px;
        }}
        QTabBar::tab:hover {{ background: {colors.control_background}; color: {colors.text}; }}
        QTabBar::tab:selected {{
            background: transparent; border-bottom-color: {colors.blue};
            color: {colors.text}; font-weight: 600;
        }}
        QLineEdit, QComboBox, QSpinBox {{
            background: {colors.control_background}; border: 1px solid {colors.control_border};
            border-radius: 4px; min-height: 30px; padding: 1px 10px; color: {colors.text};
        }}
        QSpinBox {{ padding-right: 32px; }}
        QSpinBox::up-button, QSpinBox::down-button {{
            subcontrol-origin: border; width: 26px; height: 16px;
            background: {colors.control_background}; border-left: 1px solid {colors.control_border};
        }}
        QSpinBox::up-button {{
            subcontrol-position: top right; border-bottom: 1px solid {colors.control_border};
            border-top-right-radius: 4px;
        }}
        QSpinBox::down-button {{
            subcontrol-position: bottom right; border-bottom-right-radius: 4px;
        }}
        QSpinBox::up-button:hover, QSpinBox::down-button:hover {{
            background: {colors.blue_dark_hover};
        }}
        QSpinBox::up-arrow {{ image: url("{_SPINBOX_UP_ICON}"); width: 10px; height: 10px; }}
        QSpinBox::down-arrow {{ image: url("{_SPINBOX_DOWN_ICON}"); width: 10px; height: 10px; }}
        QLineEdit:focus, QComboBox:focus, QSpinBox:focus {{ border: 2px solid {colors.blue}; }}
        QToolButton#themeButton {{
            background: transparent; border: 1px solid {colors.panel_border};
            border-radius: 7px; min-width: 32px; max-width: 32px; min-height: 32px; max-height: 32px;
            font-size: 16px; padding: 0;
        }}
        QToolButton#themeButton:hover {{ background: {colors.blue_dark_hover}; border-color: {colors.blue}; }}
        QToolButton#iconAction {{
            background: transparent; border: 1px solid {colors.panel_border}; border-radius: 7px;
        }}
        QToolButton#iconAction:hover {{ background: {colors.blue_dark_hover}; border-color: {colors.blue}; }}
        QToolButton#iconAction:disabled {{
            background: transparent; border-color: {colors.panel_border};
        }}
        QToolButton#headerIconAction {{
            background: transparent; border: 0; border-radius: 6px; padding: 0;
        }}
        QToolButton#headerIconAction:hover {{
            background: {colors.blue_dark_hover};
        }}
        QToolButton#headerIconAction:disabled {{
            background: transparent;
        }}
        QToolButton#subscriptionRowAction,
        QToolButton#usersRowAction,
        QToolButton#backupRowAction,
        QToolButton#monitorRowAction {{
            background: transparent; border: 0;
            border-radius: 5px; padding: 0;
        }}
        QToolButton#subscriptionRowAction:hover,
        QToolButton#usersRowAction:hover,
        QToolButton#backupRowAction:hover,
        QToolButton#monitorRowAction:hover {{
            background: {colors.blue_dark_hover}; border: 0;
        }}
        QToolButton#subscriptionRowAction:disabled,
        QToolButton#usersRowAction:disabled,
        QToolButton#backupRowAction:disabled,
        QToolButton#monitorRowAction:disabled {{
            background: transparent; border: 0;
        }}
        QComboBox QAbstractItemView {{
            background: {colors.panel_background}; border: 1px solid {colors.panel_border};
            selection-background-color: {colors.blue_dark_hover}; selection-color: {colors.text};
            padding: 5px;
        }}
        QMenu {{
            background: {colors.panel_background}; border: 1px solid {colors.panel_border};
            color: {colors.text}; padding: 5px;
        }}
        QMenu::item {{ padding: 6px 24px 6px 10px; border-radius: 4px; }}
        QMenu::separator {{ height: 1px; background: {colors.panel_border}; margin: 4px 8px; }}
        QMenu::item:selected {{ background: {colors.blue_dark_hover}; }}
        QMenu::indicator:checked {{ color: {colors.blue}; }}
        QCheckBox#monitorEnabledCheck {{ spacing: 0; }}
        QCheckBox#monitorEnabledCheck::indicator {{
            width: 14px; height: 14px; border: 1px solid {colors.muted_text};
            border-radius: 4px; background: {colors.control_background};
        }}
        QCheckBox#monitorEnabledCheck::indicator:hover {{
            border-color: {colors.blue}; background: {colors.blue_dark_hover};
        }}
        QCheckBox#monitorEnabledCheck::indicator:checked {{
            border-color: {colors.success}; background: {colors.success};
        }}
        QCheckBox#monitorEnabledCheck::indicator:indeterminate {{
            border-color: {colors.success}; background: {colors.success};
        }}
        QPushButton {{
            background: transparent; border: 1px solid {colors.control_border}; border-radius: 4px;
            min-height: 32px; padding: 2px 14px; font-size: 15px; font-weight: 500;
        }}
        QPushButton:hover {{ background: {colors.blue_dark_hover}; border-color: {colors.blue}; }}
        QPushButton:pressed {{ background: {colors.control_background}; }}
        QPushButton:disabled {{ color: {colors.muted_text}; background: {colors.control_background}; border-color: {colors.control_border}; }}
        QPushButton#primaryAction {{ background: {colors.blue}; border-color: {colors.blue_hover}; color: white; }}
        QPushButton#primaryAction:hover {{ background: {colors.blue_hover}; }}
        QPushButton#primaryAction, QPushButton#operationAction {{
            padding-left: 2px; padding-right: 2px;
        }}
        QPushButton#primaryAction:disabled, QPushButton#operationAction:disabled {{
            color: {colors.muted_text}; background: {colors.control_background}; border-color: {colors.control_border};
        }}
        QLabel#deployHint {{ color: {colors.muted_text}; font-size: 13px; }}
        QLabel#deployFlowArrow {{ color: {colors.amber}; font-size: 16px; font-weight: 700; }}
        QLabel#usersStatus, QLabel#managementStatus {{
            background: transparent; border: 0; color: {colors.muted_text};
            font-size: 12px; min-height: 18px; padding: 0;
        }}
        QLabel#managementStatus {{ font-size: 14px; }}
        QLabel#monitorMutedStatus, QLabel#monitorTelegramStatus, QLabel#monitorNextCheckStatus {{
            background: transparent; border: 0; color: {colors.muted_text};
        }}
        QLabel#monitorTelegramStatus[state="online"] {{ color: {colors.success}; }}
        QLabel#monitorNextCheckStatus {{ color: {colors.success}; font-weight: 600; }}
        QLabel#monitorTelegramStatus[state="starting"] {{ color: {colors.amber}; }}
        QLabel#monitorTelegramStatus[state="offline_reconnecting"] {{ color: {colors.error}; }}
        QLabel#telegramStatus, QLabel#monitorTelegramStatus {{
            font-size: 11px; font-weight: 500;
        }}
        QLabel#usersStatus[state="connecting"], QLabel#usersStatus[state="loading"] {{ font-size: 14px; }}
        QLabel#usersStatus[state="connecting"], QLabel#usersStatus[state="loading"], QLabel#managementStatus[state="loading"] {{
            color: {colors.text};
        }}
        QLabel#usersStatus[state="ready"], QLabel#managementStatus[state="ready"] {{ color: {colors.success}; }}
        QLabel#usersStatus[state="error"], QLabel#managementStatus[state="error"] {{
            background: {colors.control_background}; border: 1px solid {colors.control_border};
            border-radius: 4px; color: {colors.error}; padding: 7px 9px;
        }}
        QPlainTextEdit#managementDetailsText {{
            background: {colors.control_background}; border: 1px solid {colors.control_border};
            border-radius: 4px; color: {colors.text}; padding: 6px;
        }}
        QLabel#managementDockerLabel {{ color: {colors.muted_text}; }}
        QLabel#subscriptionNameLabel {{ font-size: 12px; font-weight: 600; }}
        QLabel#subscriptionServerStatus {{
            color: {colors.muted_text}; font-size: 12px;
        }}
        QLabel#subscriptionServerStatus[state="ready"] {{ color: {colors.success}; }}
        QLabel#subscriptionServerStatus[state="unavailable"] {{ color: {colors.amber}; }}
        QLabel#subscriptionServerStatus[state="error"] {{ color: {colors.error}; }}
        QLabel#publishedSubscriptionsTitle {{ font-size: 11px; font-weight: 600; }}
        QLabel#managementDockerValue {{ color: {colors.text}; font-weight: 600; }}
        QLabel#managementDockerValue[state="good"] {{ color: {colors.success}; }}
        QLabel#managementDockerValue[state="bad"] {{ color: {colors.error}; }}
        QFrame#managementBaseSecurityDivider {{ background: {colors.control_border}; border: 0; max-height: 1px; }}
        QToolButton#managementDockerIconAction {{
            background: {colors.control_background}; border: 1px solid {colors.control_border};
            border-radius: 5px; min-width: 28px; max-width: 28px; min-height: 28px; max-height: 28px;
        }}
        QToolButton#managementDockerIconAction:hover {{ background: {colors.blue_dark_hover}; border-color: {colors.blue}; }}
        QToolButton#managementDockerIconAction:disabled {{
            background: {colors.control_background}; border-color: {colors.control_border};
        }}
        QLabel#warning {{
            background: {colors.warning_background}; border: 1px solid {colors.deploy_border};
            border-radius: 4px; color: {colors.amber}; padding: 12px; font-weight: 600;
        }}
        QPlainTextEdit#operationLog {{
            background: {colors.log_background}; border: 1px solid {colors.panel_border}; border-radius: 8px;
            color: {colors.muted_text}; font-family: monospace; font-size: 13px; padding: 8px;
        }}
        QTableWidget {{
            background: {colors.panel_background}; border: 1px solid {colors.panel_border};
            border-radius: 8px; gridline-color: {colors.panel_border}; color: {colors.text};
            selection-background-color: {colors.blue_dark_hover}; selection-color: {colors.text};
        }}
        QTableWidget#managementTable, QTableWidget#backupTable {{ border: 0; border-radius: 0; }}
        QTableWidget#usersTable,
        QTableWidget#subscriptionSources,
        QTableWidget#backupTable {{ font-size: 12px; }}
        QTableWidget::item:selected {{ background: {colors.blue_dark_hover}; color: {colors.text}; }}
        QHeaderView::section {{
            background: {colors.panel_background}; border: 0; border-bottom: 1px solid {colors.panel_border};
            color: {colors.muted_text}; padding: 7px 10px; font-weight: 600;
        }}
        QHeaderView#usersTableHeader,
        QHeaderView#subscriptionSourcesHeader,
        QHeaderView#backupTableHeader {{ font-size: 11px; }}
    """  # noqa: E501 -- embedded Qt stylesheet
