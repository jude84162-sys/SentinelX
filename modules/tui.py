# modules/tui.py
"""
SentinelX - Terminal UI
Interactive TUI using Textual (optional).

Install: pip install textual
"""

import os
import logging
from datetime import datetime

logger = logging.getLogger("SentinelX.tui")

try:
    from textual.app import App, ComposeResult
    from textual.containers import Container, Horizontal, Vertical
    from textual.widgets import Header, Footer, Static, DataTable, TabbedContent, TabPane
    from textual.reactive import reactive
    HAS_TEXTUAL = True
except ImportError:
    HAS_TEXTUAL = False


if HAS_TEXTUAL:
    class SentinelXApp(App):
        """SentinelX Terminal UI."""

        CSS = """
        Screen {
            background: $surface;
        }
        .section-title {
            background: $primary;
            color: $text;
            padding: 1;
            text-align: center;
            text-style: bold;
        }
        DataTable {
            height: 1fr;
        }
        .info {
            padding: 1;
            color: $text-muted;
        }
        """

        BINDINGS = [
            ("q", "quit", "Quit"),
            ("r", "refresh", "Refresh"),
            ("a", "analyze", "Analyze"),
        ]

        def compose(self) -> ComposeResult:
            yield Header()
            with TabbedContent():
                with TabPane("Overview", id="overview"):
                    yield Static("Loading...", id="overview-content", classes="info")
                with TabPane("Processes", id="processes"):
                    yield DataTable(id="processes-table")
                with TabPane("Resources", id="resources"):
                    yield Static("Loading...", id="resources-content", classes="info")
                with TabPane("Files", id="files"):
                    yield Static("Loading...", id="files-content", classes="info")
                with TabPane("Alerts", id="alerts"):
                    yield DataTable(id="alerts-table")
            yield Footer()

        def on_mount(self):
            self.load_overview()
            self.load_processes()
            self.load_resources()
            self.load_alerts()
            self.set_interval(5.0, self.load_overview)

        def load_overview(self):
            try:
                from modules.env_detect import get_environment, get_env_label
                env = get_environment()
                label = get_env_label(env)

                content = (
                    f"Environment: {label}\n"
                    f"Platform:    {env['platform']}\n"
                    f"Python:      {env['python']}\n"
                    f"Root:        {'YES' if env['is_root'] else 'no'}\n"
                    f"Updated:     {datetime.now().strftime('%H:%M:%S')}"
                )
                self.query_one("#overview-content", Static).update(content)
            except Exception as e:
                self.query_one("#overview-content", Static).update(f"Error: {e}")

        def load_processes(self):
            try:
                from modules.process import run_process_triage
                table = self.query_one("#processes-table", DataTable)
                table.clear(columns=True)
                table.add_columns("PID", "Name", "CPU%", "MEM%")

                result = run_process_triage()
                for p in result.get("processes", [])[:30]:
                    table.add_row(
                        str(p.get("pid", "?")),
                        p.get("name", "?")[:25],
                        str(p.get("cpu", 0)),
                        str(p.get("memory", 0)),
                    )
            except Exception as e:
                logger.debug(f"Process load failed: {e}")

        def load_resources(self):
            try:
                from modules.resources import run_resource_check
                result = run_resource_check()

                bat = result.get("battery") or {}
                content = (
                    f"CPU:     {result['system_load'].get('cpu_percent', 0)}%\n"
                    f"Memory:  {result['system_load'].get('memory_percent', 0)}%\n"
                    f"Battery: {bat.get('percentage', 'N/A')}%\n"
                    f"Temp:    {bat.get('temperature', 'N/A')}°C\n"
                    f"Warnings: {len(result.get('warnings', []))}"
                )
                self.query_one("#resources-content", Static).update(content)
            except Exception as e:
                logger.debug(f"Resources load failed: {e}")

        def load_alerts(self):
            try:
                from modules.cache_db import get_recent_alerts
                table = self.query_one("#alerts-table", DataTable)
                table.clear(columns=True)
                table.add_columns("Time", "Severity", "Message")

                for alert in get_recent_alerts(20):
                    table.add_row(
                        alert["timestamp"][11:19],
                        alert["severity"],
                        alert["message"][:60],
                    )
            except Exception as e:
                logger.debug(f"Alerts load failed: {e}")

        def action_refresh(self):
            self.load_overview()
            self.load_processes()
            self.load_resources()
            self.load_alerts()

        def action_analyze(self):
            self.notify("Running analysis... (check console)")


def run_tui():
    """Run the TUI."""
    if not HAS_TEXTUAL:
        print("[!] Textual not installed.")
        print("    Run: pip install textual")
        return

    app = SentinelXApp()
    app.run()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    run_tui()
