"""
app.py - Application controller for 221B threat hunting dashboard.

This module handles UI construction and database connection through
the ionic_scripting_framework (isf). It creates an interactive dashboard
using ipywidgets.
"""

import ipywidgets as widgets
from IPython.display import display, clear_output, HTML
import pandas as pd
import re
import json
import os
import time
import datetime
from datetime import date
from multiprocessing import cpu_count
from ionic_scripting_framework import isf
from strategies import HuntStrategy
import html as html_lib  # For HTML escaping

# Try to import plotly for visualizations (optional)
try:
    import plotly.graph_objects as go
    HAS_PLOTLY = True
except ImportError:
    HAS_PLOTLY = False


# Visual styling constants for severity indicators (enhanced with modern colors)
COLOR_HIGH_SEVERITY_BG = '#fee2e2'  # Light red background (Tailwind red-100)
COLOR_HIGH_SEVERITY_BADGE = '#dc2626'  # Red badge (Tailwind red-600)
COLOR_MEDIUM_SEVERITY_BG = '#fef3c7'  # Light amber background (Tailwind amber-100)
COLOR_MEDIUM_SEVERITY_BADGE = '#f59e0b'  # Amber badge (Tailwind amber-500)
COLOR_LOW_SEVERITY_BG = '#d1fae5'  # Light green background (Tailwind green-100)
COLOR_LOW_SEVERITY_BADGE = '#10b981'  # Green badge (Tailwind green-500)

# Analysis and display constants
CRITICAL_SEVERITY_THRESHOLD = 90  # Score threshold for critical threats (immediate action required)
HIGH_SEVERITY_THRESHOLD = 75  # Score threshold for high-severity threats
MEDIUM_SEVERITY_THRESHOLD = 50  # Score threshold for medium-severity threats
MAX_DISPLAY_ITEMS = 20  # Maximum items to display in correlation/triage views
STRING_TRUNCATE_LENGTH = 50  # Length to truncate long strings for display

# Common HTML/CSS gradient patterns - consolidated to reduce duplication
# across all dashboard visualizations
GRADIENT_DARK_CARD = "linear-gradient(135deg, #1e293b 0%, #334155 100%)"
GRADIENT_RED_CRITICAL = "linear-gradient(135deg, #dc2626 0%, #991b1b 100%)"
GRADIENT_RED_DANGER = "linear-gradient(135deg, #e74c3c 0%, #c0392b 100%)"  # Used for alerts/triage
GRADIENT_AMBER_WARNING = "linear-gradient(135deg, #f59e0b 0%, #d97706 100%)"
GRADIENT_GREEN_SUCCESS = "linear-gradient(135deg, #10b981 0%, #059669 100%)"
GRADIENT_BLUE_PRIMARY = "linear-gradient(135deg, #6366f1 0%, #4f46e5 100%)"  # Primary indigo
GRADIENT_BLUE_PURPLE = "linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%)"  # Indigo to purple
GRADIENT_PURPLE_DEEP = "linear-gradient(135deg, #8b5cf6 0%, #7c3aed 100%)"  # Deep purple
GRADIENT_PURPLE_VIOLET = "linear-gradient(135deg, #667eea 0%, #764ba2 100%)"  # Violet blend
GRADIENT_PINK_MAGENTA = "linear-gradient(135deg, #ec4899 0%, #db2777 100%)"  # Pink/magenta

# Common CSS style patterns - consolidated to improve maintainability
CSS_METRIC_VALUE = "font-size: 3em; font-weight: bold; margin-bottom: 8px;"
CSS_METRIC_LABEL = "font-size: 0.95em; opacity: 0.95;"
CSS_METRIC_SUBLABEL = "font-size: 0.85em; opacity: 0.8; margin-top: 4px;"
CSS_STAT_BOX = "background: rgba(255,255,255,0.2); padding: 15px; border-radius: 8px;"
CSS_CARD_TRANSLUCENT = "background: rgba(255,255,255,0.15); padding: 18px; border-radius: 12px; backdrop-filter: blur(10px); border: 1px solid rgba(255,255,255,0.2);"
CSS_HEADING_LARGE = "font-size: 2em; font-weight: bold;"
CSS_TEXT_SUBTLE = "font-size: 0.9em; opacity: 0.9;"
CSS_TEXT_MUTED = "font-size: 0.9em; opacity: 0.95;"
CSS_CONTENT_BOX = "padding: 8px; border: 1px solid #ddd;"
CSS_LINE_HEIGHT = "line-height: 1.8;"


class WatsonDashboard:
    """
    Interactive dashboard for threat hunting using various strategies.
    
    Connects to IONIC database via isf, dynamically builds UI based on
    selected table schema, and executes hunt strategies on the data.
    """
    
    def __init__(self, strategies: list, cache_dir: str = '.221b_cache', cache_days: int = 7):
        """
        Initialize the WatsonDashboard.
        
        Args:
            strategies: List of HuntStrategy objects to make available
            cache_dir: Directory to store cached data (default: '.221b_cache')
            cache_days: Number of days to keep cached tables list (default: 7)
        """
        self.strategies = strategies
        self.all_tables = []
        self.cache_dir = cache_dir
        self.cache_days = cache_days
        self.tables_cache_file = os.path.join(cache_dir, 'available_tables.json')
        
        # Create cache directory if it doesn't exist
        os.makedirs(cache_dir, exist_ok=True)
        
        # UI Components - will be created per tab
        self.tab_widget = None
        self.strategy_tab_contents = {}
        
        # Results storage for cross-strategy correlation
        self.strategy_results = {}  # Dict to store results from each strategy
        
        # Performance tracking for strategy execution
        self.strategy_performance = {}  # Dict to store execution time and stats
        
        # Initialize UI
        self._initialize_ui()
    
    def _initialize_ui(self):
        """Set up the initial UI components."""
        # Query available tables once
        self.all_tables = self._get_available_tables()
        
        # Create tabs for strategies with all widgets inside each tab
        self._create_strategy_tabs()
    
    def _get_cache_age(self) -> float:
        """
        Get the age of the cache in days.
        
        Returns:
            Age in days, or -1 if cache doesn't exist
        """
        if os.path.exists(self.tables_cache_file):
            try:
                with open(self.tables_cache_file, 'r') as f:
                    cache_data = json.load(f)
                cache_time = datetime.datetime.fromisoformat(cache_data['timestamp'])
                # Ensure timezone-naive comparison
                if cache_time.tzinfo is not None:
                    cache_time = cache_time.replace(tzinfo=None)
                age_seconds = (datetime.datetime.now() - cache_time).total_seconds()
                return age_seconds / 86400  # Convert to days
            except (FileNotFoundError, json.JSONDecodeError, KeyError, ValueError):
                return -1
        return -1
    
    def _refresh_cache(self) -> list:
        """
        Force refresh the table cache from the database.
        
        Returns:
            Updated list of table names
        """
        print("🔄 Manually refreshing table cache...")
        
        # Delete old cache if it exists
        if os.path.exists(self.tables_cache_file):
            os.remove(self.tables_cache_file)
        
        # Force re-query
        tables = self._get_available_tables()
        print("✅ Cache refreshed successfully!")
        return tables
    
    def _get_available_tables(self) -> list:
        """
        Query information_schema.tables to get available tables.
        Uses local cache if available and fresh (within cache_days).
        
        Returns:
            List of table names
        """
        # Check if cache exists and is fresh
        if os.path.exists(self.tables_cache_file):
            try:
                with open(self.tables_cache_file, 'r') as f:
                    cache_data = json.load(f)
                
                # Check cache timestamp
                cache_time = datetime.datetime.fromisoformat(cache_data['timestamp'])
                # Ensure timezone-naive comparison
                if cache_time.tzinfo is not None:
                    cache_time = cache_time.replace(tzinfo=None)
                age_seconds = (datetime.datetime.now() - cache_time).total_seconds()
                age_days = age_seconds / 86400  # Convert seconds to days
                
                if age_days < self.cache_days:
                    # Add indicator for stale cache (approaching expiry)
                    if age_days > self.cache_days * 0.8:
                        print(f"📦 Using cached table list (age: {age_days:.1f} days) ⚠️ Consider refreshing soon")
                    else:
                        print(f"📦 Using cached table list (age: {age_days:.1f} days) ✅ Fresh")
                    return cache_data['tables']
                else:
                    print(f"⏰ Cache expired (age: {age_days:.1f} days), refreshing...")
            except (json.JSONDecodeError, KeyError, ValueError) as e:
                print(f"⚠️ Cache file corrupted, refreshing... ({e})")
        
        # Cache miss or expired - query database
        try:
            print("🔄 Querying database for available tables...")
            query = """
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema NOT IN ('information_schema', 'pg_catalog')
            ORDER BY table_name
            """
            df = isf.run_query(query)
            
            if df is not None and not df.empty:
                tables = df['table_name'].tolist()
                
                # Save to cache
                cache_data = {
                    'timestamp': datetime.datetime.now().isoformat(),
                    'tables': tables
                }
                with open(self.tables_cache_file, 'w') as f:
                    json.dump(cache_data, f, indent=2)
                
                print(f"✅ Cached {len(tables)} tables")
                return tables
            else:
                return ['No tables available']
        except Exception as e:
            print(f"Error fetching tables: {e}")
            return ['Error loading tables']
    
    def _get_input_descriptions(self, strategy: HuntStrategy) -> dict:
        """
        Get descriptions and examples for each required input of a strategy.
        
        Args:
            strategy: The hunt strategy
            
        Returns:
            Dictionary mapping input names to (description, example) tuples
        """
        descriptions = {
            'timestamp': (
                "Time field for analyzing temporal patterns",
                "Examples: ts, timestamp, event_time, @timestamp"
            ),
            'source_ip': (
                "Source IP address field",
                "Examples: id.orig_h, src_ip, source.ip, client_ip"
            ),
            'dest_ip': (
                "Destination IP address field",
                "Examples: id.resp_h, dst_ip, dest.ip, server_ip"
            ),
            'target_string': (
                "String field to analyze for entropy (DNS queries, URLs, User-Agents, etc.)",
                "Examples: query (DNS), host (HTTP), user_agent, uri, domain"
            ),
            'bytes_out': (
                "Bytes sent/uploaded field",
                "Examples: orig_bytes, bytes_sent, tx_bytes, upload_bytes"
            ),
            'bytes_in': (
                "Bytes received/downloaded field",
                "Examples: resp_bytes, bytes_received, rx_bytes, download_bytes"
            )
        }
        
        return {inp: descriptions.get(inp, ("Required field", "")) 
                for inp in strategy.required_inputs}
    
    def _get_strategy_recommendation(self, strategy: HuntStrategy) -> str:
        """
        Get contextual recommendation for when to use a strategy.
        
        Args:
            strategy: The hunt strategy
            
        Returns:
            HTML string with recommendation
        """
        recommendations = {
            'Beacon Hunter': '🎯 <b>Best for:</b> Network logs (firewall, proxy, DNS). Use when investigating suspected C2 communications or malware callbacks.',
            'Entropy Analyzer': '🎯 <b>Best for:</b> DNS logs, URL logs, user-agent strings. Perfect for finding DGA domains, encoded data, or obfuscation.',
            'Exfiltration Monitor': '🎯 <b>Best for:</b> Network flow logs with byte counts. Ideal for identifying data theft via unusual upload patterns.',
            'Port Scan Detector': '🎯 <b>Best for:</b> Firewall or connection logs. Essential for catching reconnaissance and attack preparation.',
            'Brute Force Detector': '🎯 <b>Best for:</b> Authentication logs (VPN, SSH, web apps). Critical for defending against credential attacks.',
            'Protocol Tunneling Detector': '🎯 <b>Best for:</b> Network logs with port/protocol info. Finds covert channels and protocol misuse.',
            'Lateral Movement Detector': '🎯 <b>Best for:</b> Internal network logs. Crucial for detecting attackers spreading through your network.',
            'Data Hoarding Detector': '🎯 <b>Best for:</b> File access or database query logs. Catches insider threats collecting data before exfiltration.',
            'Time Anomaly Detector': '🎯 <b>Best for:</b> Any logs with timestamps. Great for finding off-hours access and weekend attacks.',
            'Geo-Anomaly Detector': '🎯 <b>Best for:</b> Logs with IP addresses (web, VPN, auth). Excellent for detecting account compromise and location-based threats.',
            'User-Agent Anomaly Detector': '🎯 <b>Best for:</b> Web/proxy logs with user-agent strings. Identifies attack tools, bots, and scanners.',
            'Crypto Mining Detector': '🎯 <b>Best for:</b> Network logs with IPs and ports. Finds cryptojacking malware and policy violations.',
            'DNS Anomaly Detector': '🎯 <b>Best for:</b> DNS query logs. Catches DGA malware, DNS tunneling, and malicious domain lookups.',
            'Account Takeover Detector': '🎯 <b>Best for:</b> Authentication logs with IPs and usernames. Detects credential theft and account compromise.',
            'Data Staging Detector': '🎯 <b>Best for:</b> File operation logs. Identifies data collection before exfiltration attempts.'
        }
        
        recommendation = recommendations.get(strategy.name, '🎯 <b>Use this strategy</b> for specialized threat hunting.')
        
        return f'<div style="background: #e3f2fd; padding: 12px; border-radius: 8px; margin: 10px 0; border-left: 4px solid #2196f3;"><span style="color: #1565c0;">{recommendation}</span></div>'
    
    def _create_strategy_tabs(self):
        """Create tab widget for strategies with all UI elements inside each tab."""
        tab_contents = []
        
        for i, strategy in enumerate(self.strategies):
            # Create components for this specific tab
            tab_data = {
                'strategy': strategy,
                'table_search': widgets.Text(
                    placeholder='Search tables...',
                    description='Filter:',
                    style={'description_width': 'initial'}
                ),
                'table_dropdown': widgets.Dropdown(
                    options=self.all_tables,
                    description='Select Table:',
                    style={'description_width': 'initial'}
                ),
                'load_table_button': widgets.Button(
                    description='Load Table Schema',
                    button_style='info',
                    icon='database'
                ),
                'column_dropdowns': {},
                'column_mapping_container': widgets.VBox([]),
                'limit_input': widgets.IntText(
                    value=10000,
                    description='Row Limit:',
                    min=1,
                    max=1000000,
                    style={'description_width': 'initial'}
                ),
                'enable_date_filter': widgets.Checkbox(
                    value=False,
                    description='Enable Date Filter',
                    style={'description_width': 'initial'}
                ),
                'start_date': widgets.DatePicker(
                    description='Start Date:',
                    disabled=True,
                    style={'description_width': 'initial'}
                ),
                'end_date': widgets.DatePicker(
                    description='End Date:',
                    disabled=True,
                    style={'description_width': 'initial'}
                ),
                'run_button': widgets.Button(
                    description='Run Analysis',
                    button_style='success',
                    icon='search'
                ),
                'output_widget': widgets.Output(),
                'available_columns': []
            }
            
            # Store tab data
            self.strategy_tab_contents[i] = tab_data
            
            # Set up event handlers with proper context
            # Use closures to capture the correct tab index
            def make_table_search_handler(tab_idx):
                return lambda change: self._on_table_search(change, tab_idx)
            
            def make_load_table_handler(tab_idx):
                return lambda btn: self._on_load_table(btn, tab_idx)
            
            def make_run_analysis_handler(tab_idx):
                return lambda btn: self._run_analysis(btn, tab_idx)
            
            def make_date_filter_handler(tab_idx):
                return lambda change: self._on_date_filter_toggle(change, tab_idx)
            
            tab_data['table_search'].observe(make_table_search_handler(i), names='value')
            tab_data['load_table_button'].on_click(make_load_table_handler(i))
            tab_data['run_button'].on_click(make_run_analysis_handler(i))
            tab_data['enable_date_filter'].observe(make_date_filter_handler(i), names='value')
            
            # Create strategy description with input details
            input_descriptions = self._get_input_descriptions(strategy)
            inputs_html = ""
            for inp, (desc, example) in input_descriptions.items():
                inputs_html += f"""
                <div style="margin: 10px 0; padding: 8px; background: #f8f9fa; color: #212529; border-left: 3px solid #007bff;">
                    <b>{inp}:</b> {desc}<br/>
                    <i style="color: #495057; font-size: 0.9em;">{example}</i>
                </div>
                """
            
            # Get strategy docstring with null check
            strategy_doc = strategy.__class__.__doc__
            strategy_desc = strategy_doc.strip() if strategy_doc else "No description available"
            
            # Get strategy recommendation
            recommendation_html = self._get_strategy_recommendation(strategy)
            
            description = widgets.HTML(
                value=f"""
                <div style="padding: 10px;">
                    <h3>{strategy.name}</h3>
                    <p style="margin: 10px 0;"><i>{strategy_desc}</i></p>
                    {recommendation_html}
                    <h4>Required Inputs:</h4>
                    {inputs_html}
                </div>
                """
            )
            
            # Assemble tab content
            tab_content = widgets.VBox([
                description,
                widgets.HTML("<hr>"),
                widgets.HTML("<h4>Data Source</h4>"),
                tab_data['table_search'],
                tab_data['table_dropdown'],
                tab_data['load_table_button'],
                widgets.HTML("<hr>"),
                widgets.HTML("<h4>Column Mapping</h4>"),
                tab_data['column_mapping_container'],
                widgets.HTML("<hr>"),
                widgets.HTML("<h4>Query Options</h4>"),
                tab_data['limit_input'],
                tab_data['enable_date_filter'],
                tab_data['start_date'],
                tab_data['end_date'],
                tab_data['run_button'],
                widgets.HTML("<hr>"),
                tab_data['output_widget']
            ])
            
            tab_contents.append(tab_content)
        
        # Create Tab widget
        self.tab_widget = widgets.Tab(children=tab_contents)
        
        # Set tab titles
        for i, strategy in enumerate(self.strategies):
            # Use first word as tab title, with fallback if name is empty or has no words
            name_parts = strategy.name.split()
            tab_title = name_parts[0] if name_parts else f"Strategy {i+1}"
            self.tab_widget.set_title(i, tab_title)
    
    def _on_table_search(self, change, tab_index: int):
        """
        Handle table search/filter changes for a specific tab.
        
        Args:
            change: Change event from search text widget
            tab_index: Index of the tab
        """
        tab_data = self.strategy_tab_contents[tab_index]
        search_term = change['new'].lower()
        
        if not search_term:
            # Show all tables if search is empty
            tab_data['table_dropdown'].options = self.all_tables
        else:
            # Filter tables based on search term
            filtered_tables = [t for t in self.all_tables if search_term in t.lower()]
            tab_data['table_dropdown'].options = filtered_tables if filtered_tables else ['No matching tables']
    
    def _on_date_filter_toggle(self, change, tab_index: int):
        """
        Handle date filter enable/disable toggle.
        
        Args:
            change: Change event from checkbox widget
            tab_index: Index of the tab
        """
        tab_data = self.strategy_tab_contents[tab_index]
        enabled = change['new']
        
        # Enable/disable date picker widgets
        tab_data['start_date'].disabled = not enabled
        tab_data['end_date'].disabled = not enabled
    
    def _calculate_severity_metrics(self):
        """
        Calculate severity metrics across all strategy results.
        Consolidates duplicate calculation logic used in multiple dashboard views.
        
        Returns:
            dict: Dictionary containing severity counts, scores, and totals
        """
        metrics = {
            'total_threats': 0,
            'strategies_run': 0,
            'high_severity_count': 0,
            'medium_severity_count': 0,
            'low_severity_count': 0,
            'max_threat_score': 0,
            'all_scores': [],
            'avg_threat_score': 0
        }
        
        if not self.strategy_results:
            return metrics
        
        metrics['total_threats'] = sum(len(r['dataframe']) for r in self.strategy_results.values())
        metrics['strategies_run'] = len(self.strategy_results)
        
        for result_data in self.strategy_results.values():
            df = result_data['dataframe']
            score_cols = [col for col in df.columns if col.endswith('_score')]
            if score_cols:
                scores = df[score_cols[0]]
                metrics['all_scores'].extend(scores.tolist())
                metrics['high_severity_count'] += len(df[scores >= HIGH_SEVERITY_THRESHOLD])
                metrics['medium_severity_count'] += len(df[(scores >= MEDIUM_SEVERITY_THRESHOLD) & (scores < HIGH_SEVERITY_THRESHOLD)])
                metrics['low_severity_count'] += len(df[scores < MEDIUM_SEVERITY_THRESHOLD])
                metrics['max_threat_score'] = max(metrics['max_threat_score'], scores.max())
        
        if metrics['all_scores']:
            metrics['avg_threat_score'] = sum(metrics['all_scores']) / len(metrics['all_scores'])
        
        return metrics
    
    def _show_threat_metrics_dashboard(self):
        """
        Display a comprehensive real-time threat metrics dashboard showing
        aggregated statistics across all strategies.
        """
        if not self.strategy_results:
            print("⚠️ No analysis results available. Run some strategies first to see metrics.")
            return
        
        # Use consolidated helper method to calculate metrics
        metrics = self._calculate_severity_metrics()
        total_threats = metrics['total_threats']
        strategies_run = metrics['strategies_run']
        high_severity_count = metrics['high_severity_count']
        medium_severity_count = metrics['medium_severity_count']
        low_severity_count = metrics['low_severity_count']
        max_threat_score = metrics['max_threat_score']
        avg_threat_score = metrics['avg_threat_score']
        all_scores = metrics['all_scores']
        
        # Build dashboard HTML using consolidated gradient constants
        dashboard_html = f"""
        <div style="background: {GRADIENT_DARK_CARD}; color: white; padding: 32px; border-radius: 20px; margin: 20px 0; box-shadow: 0 10px 25px rgba(0,0,0,0.3);">
            <h2 style="margin-top: 0; font-size: 2em; display: flex; align-items: center; gap: 12px; margin-bottom: 30px;">
                🛡️ Real-Time Threat Intelligence Dashboard
            </h2>
            
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 20px; margin-bottom: 30px;">
                <div style="background: {GRADIENT_RED_CRITICAL}; padding: 24px; border-radius: 16px; box-shadow: 0 4px 6px rgba(0,0,0,0.2); border: 2px solid rgba(255,255,255,0.1);">
                    <div style="{CSS_METRIC_VALUE}">🔴 {high_severity_count}</div>
                    <div style="{CSS_METRIC_LABEL}">Critical Threats</div>
                    <div style="{CSS_METRIC_SUBLABEL}">Score ≥ 75</div>
                </div>
                
                <div style="background: {GRADIENT_AMBER_WARNING}; padding: 24px; border-radius: 16px; box-shadow: 0 4px 6px rgba(0,0,0,0.2); border: 2px solid rgba(255,255,255,0.1);">
                    <div style="{CSS_METRIC_VALUE}">🟡 {medium_severity_count}</div>
                    <div style="{CSS_METRIC_LABEL}">Medium Threats</div>
                    <div style="{CSS_METRIC_SUBLABEL}">Score 50-74</div>
                </div>
                
                <div style="background: {GRADIENT_GREEN_SUCCESS}; padding: 24px; border-radius: 16px; box-shadow: 0 4px 6px rgba(0,0,0,0.2); border: 2px solid rgba(255,255,255,0.1);">
                    <div style="{CSS_METRIC_VALUE}">🟢 {low_severity_count}</div>
                    <div style="{CSS_METRIC_LABEL}">Low Priority</div>
                    <div style="{CSS_METRIC_SUBLABEL}">Score < 50</div>
                </div>
                
                <div style="background: {GRADIENT_BLUE_PRIMARY}; padding: 24px; border-radius: 16px; box-shadow: 0 4px 6px rgba(0,0,0,0.2); border: 2px solid rgba(255,255,255,0.1);">
                    <div style="{CSS_METRIC_VALUE}">📊 {total_threats}</div>
                    <div style="{CSS_METRIC_LABEL}">Total Detections</div>
                    <div style="{CSS_METRIC_SUBLABEL}">Across {strategies_run} strategies</div>
                </div>
                
                <div style="background: {GRADIENT_PURPLE_DEEP}; padding: 24px; border-radius: 16px; box-shadow: 0 4px 6px rgba(0,0,0,0.2); border: 2px solid rgba(255,255,255,0.1);">
                    <div style="{CSS_METRIC_VALUE}">⚡ {avg_threat_score:.1f}</div>
                    <div style="{CSS_METRIC_LABEL}">Average Score</div>
                    <div style="{CSS_METRIC_SUBLABEL}">Threat severity</div>
                </div>
                
                <div style="background: {GRADIENT_PINK_MAGENTA}; padding: 24px; border-radius: 16px; box-shadow: 0 4px 6px rgba(0,0,0,0.2); border: 2px solid rgba(255,255,255,0.1);">
                    <div style="{CSS_METRIC_VALUE}">⚠️ {max_threat_score:.1f}</div>
                    <div style="{CSS_METRIC_LABEL}">Peak Threat</div>
                    <div style="{CSS_METRIC_SUBLABEL}">Highest score</div>
                </div>
            </div>
            
            <div style="background: rgba(255,255,255,0.1); padding: 20px; border-radius: 12px; backdrop-filter: blur(10px);">
                <h3 style="margin-top: 0; margin-bottom: 15px;">📈 Strategy Performance</h3>
                <div style="display: flex; flex-wrap: wrap; gap: 10px;">
        """
        
        # Add strategy badges
        for strategy_name, result_data in self.strategy_results.items():
            threat_count = len(result_data['dataframe'])
            dashboard_html += f"""
                <div style="background: rgba(255,255,255,0.15); padding: 12px 20px; border-radius: 8px; border: 1px solid rgba(255,255,255,0.2);">
                    <div style="font-weight: bold; margin-bottom: 4px;">{strategy_name.split('(')[0].strip()}</div>
                    <div style="font-size: 1.3em; color: #fbbf24;">{threat_count} detections</div>
                </div>
            """
        
        dashboard_html += """
                </div>
            </div>
        </div>
        """
        
        display(HTML(dashboard_html))
        
        # Add Plotly visualizations if available
        if HAS_PLOTLY and all_scores:
            self._show_strategy_comparison_chart()
    
    def _show_strategy_comparison_chart(self):
        """
        Display a comparative chart showing effectiveness of different strategies.
        """
        if not HAS_PLOTLY or not self.strategy_results:
            return
        
        # Prepare data for comparison
        strategy_names = []
        detection_counts = []
        avg_scores = []
        high_severity_counts = []
        
        for strategy_name, result_data in self.strategy_results.items():
            df = result_data['dataframe']
            strategy_names.append(strategy_name.split('(')[0].strip())
            detection_counts.append(len(df))
            
            score_cols = [col for col in df.columns if col.endswith('_score')]
            if score_cols:
                scores = df[score_cols[0]]
                avg_scores.append(scores.mean())
                high_severity_counts.append(len(df[scores >= HIGH_SEVERITY_THRESHOLD]))
            else:
                avg_scores.append(0)
                high_severity_counts.append(0)
        
        # Create subplots
        from plotly.subplots import make_subplots
        
        fig = make_subplots(
            rows=1, cols=2,
            subplot_titles=('Detection Volume by Strategy', 'Critical Threats by Strategy'),
            specs=[[{"type": "bar"}, {"type": "bar"}]]
        )
        
        # Add detection volume chart
        fig.add_trace(
            go.Bar(
                x=strategy_names,
                y=detection_counts,
                name='Total Detections',
                marker=dict(
                    color=detection_counts,
                    colorscale='Blues',
                    showscale=False,
                    line=dict(color='white', width=1)
                ),
                text=detection_counts,
                textposition='outside'
            ),
            row=1, col=1
        )
        
        # Add critical threats chart
        fig.add_trace(
            go.Bar(
                x=strategy_names,
                y=high_severity_counts,
                name='Critical Threats',
                marker=dict(
                    color=high_severity_counts,
                    colorscale='Reds',
                    showscale=False,
                    line=dict(color='white', width=1)
                ),
                text=high_severity_counts,
                textposition='outside'
            ),
            row=1, col=2
        )
        
        fig.update_xaxes(tickangle=-45, row=1, col=1)
        fig.update_xaxes(tickangle=-45, row=1, col=2)
        
        fig.update_layout(
            title_text="Strategy Effectiveness Comparison",
            showlegend=False,
            height=450,
            margin=dict(b=120)
        )
        
        display(fig)
    
    def _show_threat_velocity_gauge(self):
        """
        Display a real-time threat velocity gauge showing threats detected per time period.
        """
        if not self.strategy_results:
            print("⚠️ No analysis results available. Run some strategies first to see velocity metrics.")
            return
        
        print("=" * 80)
        print("⚡ THREAT VELOCITY METRICS")
        print("=" * 80)
        print()
        
        # Collect all threats with timestamps
        all_threats = []
        for strategy_name, result_data in self.strategy_results.items():
            df = result_data['dataframe']
            
            # Find timestamp columns
            timestamp_cols = [col for col in df.columns if 'timestamp' in col.lower() or 'time' in col.lower()]
            
            if timestamp_cols:
                ts_col = timestamp_cols[0]
                for idx, row in df.iterrows():
                    ts = row[ts_col]
                    if pd.notna(ts):
                        all_threats.append({
                            'timestamp': ts,
                            'strategy': strategy_name
                        })
        
        if not all_threats:
            print("⚠️ No timestamp data available for velocity calculation")
            return
        
        # Convert to DataFrame
        threats_df = pd.DataFrame(all_threats)
        threats_df['timestamp'] = pd.to_datetime(threats_df['timestamp'])
        
        # Calculate time span
        min_time = threats_df['timestamp'].min()
        max_time = threats_df['timestamp'].max()
        time_span_hours = (max_time - min_time).total_seconds() / 3600
        time_span_days = time_span_hours / 24
        
        total_count = len(threats_df)
        
        # Calculate velocities
        threats_per_hour = total_count / time_span_hours if time_span_hours > 0 else 0
        threats_per_day = total_count / time_span_days if time_span_days > 0 else 0
        
        # Display metrics
        print(f"📊 Time Range: {min_time.strftime('%Y-%m-%d %H:%M')} to {max_time.strftime('%Y-%m-%d %H:%M')}")
        print(f"⏱️  Duration: {time_span_days:.1f} days ({time_span_hours:.1f} hours)")
        print(f"🎯 Total Threats: {total_count:,}")
        print()
        print("⚡ Threat Velocity:")
        print(f"   • Per Hour: {threats_per_hour:.1f} threats/hour")
        print(f"   • Per Day: {threats_per_day:.1f} threats/day")
        print()
        
        # Show trend over time (by hour)
        if HAS_PLOTLY and time_span_hours > 1:
            threats_df['hour'] = threats_df['timestamp'].dt.floor('H')
            hourly_counts = threats_df.groupby('hour').size()
            
            fig = go.Figure()
            
            # Line chart for trend
            fig.add_trace(go.Scatter(
                x=hourly_counts.index,
                y=hourly_counts.values,
                mode='lines+markers',
                name='Threats per Hour',
                line=dict(color='#ef4444', width=3),
                marker=dict(size=8, color='#dc2626'),
                fill='tozeroy',
                fillcolor='rgba(239, 68, 68, 0.2)'
            ))
            
            # Add average line
            avg_line = [threats_per_hour] * len(hourly_counts)
            fig.add_trace(go.Scatter(
                x=hourly_counts.index,
                y=avg_line,
                mode='lines',
                name=f'Average ({threats_per_hour:.1f}/hr)',
                line=dict(color='#f59e0b', width=2, dash='dash')
            ))
            
            fig.update_layout(
                title='Threat Detection Velocity Over Time',
                xaxis_title='Time',
                yaxis_title='Threats Detected',
                height=400,
                hovermode='x unified',
                showlegend=True
            )
            
            display(fig)
        
        # Show top strategies by detection rate
        strategy_counts = threats_df['strategy'].value_counts()
        print("🏆 Top 5 Most Active Strategies:")
        for i, (strategy, count) in enumerate(strategy_counts.head(5).items(), 1):
            rate_per_day = count / time_span_days if time_span_days > 0 else 0
            print(f"   {i}. {strategy}: {count} threats ({rate_per_day:.1f}/day)")
        print()
    
    def _show_performance_statistics(self):
        """
        Display strategy performance statistics including execution time and detection rates.
        """
        if not self.strategy_performance:
            print("⚠️ No performance data available yet. Run some strategies first.")
            return
        
        print("=" * 80)
        print("📊 STRATEGY PERFORMANCE STATISTICS")
        print("=" * 80)
        print()
        
        # Build performance table
        perf_data = []
        for strategy_name, perf in self.strategy_performance.items():
            perf_data.append({
                'Strategy': strategy_name.split('(')[0].strip()[:30],
                'Exec Time (s)': f"{perf['execution_time']:.2f}",
                'Rows/Sec': f"{perf['rows_per_second']:.0f}",
                'Rows Analyzed': f"{perf['rows_analyzed']:,}",
                'Detections': f"{perf['detections']:,}",
                'Detection %': f"{perf['detection_rate']:.2f}%",
                'Timestamp': perf['timestamp'].strftime('%H:%M:%S')
            })
        
        perf_df = pd.DataFrame(perf_data)
        
        # Sort by execution time (fastest first)
        perf_df = perf_df.sort_values('Exec Time (s)')
        
        # Display as formatted table
        display(HTML(perf_df.to_html(index=False, escape=False, classes='table')))
        
        print()
        print("💡 Performance Tips:")
        print("   • Faster strategies are better for real-time analysis")
        print("   • High detection rates may indicate noisy data or loose thresholds")
        print("   • Low detection rates may indicate clean data or tight thresholds")
        print()
        
        # Add visualization if plotly is available
        if HAS_PLOTLY and len(perf_data) > 1:
            try:
                from plotly.subplots import make_subplots
                
                fig = make_subplots(
                    rows=1, cols=2,
                    subplot_titles=('Execution Time by Strategy', 'Throughput (Rows/Second)'),
                    specs=[[{"type": "bar"}, {"type": "bar"}]]
                )
                
                # Execution time chart
                exec_times = [perf['execution_time'] for perf in self.strategy_performance.values()]
                strategy_names = [name.split('(')[0].strip()[:20] for name in self.strategy_performance.keys()]
                
                fig.add_trace(
                    go.Bar(
                        x=strategy_names,
                        y=exec_times,
                        marker=dict(color=exec_times, colorscale='Viridis', showscale=False),
                        name='Execution Time',
                        text=[f"{t:.2f}s" for t in exec_times],
                        textposition='outside'
                    ),
                    row=1, col=1
                )
                
                # Throughput chart
                throughputs = [perf['rows_per_second'] for perf in self.strategy_performance.values()]
                
                fig.add_trace(
                    go.Bar(
                        x=strategy_names,
                        y=throughputs,
                        marker=dict(color=throughputs, colorscale='Turbo', showscale=False),
                        name='Rows/Second',
                        text=[f"{int(t)}" for t in throughputs],
                        textposition='outside'
                    ),
                    row=1, col=2
                )
                
                fig.update_xaxes(tickangle=-45, row=1, col=1)
                fig.update_xaxes(tickangle=-45, row=1, col=2)
                fig.update_yaxes(title_text="Seconds", row=1, col=1)
                fig.update_yaxes(title_text="Rows/Second", row=1, col=2)
                
                fig.update_layout(
                    showlegend=False,
                    height=450,
                    margin=dict(b=120)
                )
                
                display(fig)
                
            except Exception as e:
                print(f"⚠️ Could not generate performance charts: {e}")
    
    def _show_threat_timeline(self):
        """
        Display a temporal threat activity heatmap showing when threats were detected.
        """
        if not self.strategy_results:
            print("⚠️ No threat data available yet. Run some strategies first.")
            return
        
        print("=" * 80)
        print("📅 TEMPORAL THREAT ACTIVITY ANALYSIS")
        print("=" * 80)
        print()
        
        # Collect all timestamps from results
        timeline_data = []
        
        for strategy_name, result_data in self.strategy_results.items():
            df = result_data['dataframe']
            
            # Look for timestamp columns
            timestamp_cols = [col for col in df.columns if 'time' in col.lower() or 'date' in col.lower() or col == 'timestamp']
            
            if not timestamp_cols:
                continue
            
            ts_col = timestamp_cols[0]
            
            # Find score column
            score_cols = [col for col in df.columns if col.endswith('_score')]
            if not score_cols:
                continue
            
            score_col = score_cols[0]
            
            # Extract data
            for _, row in df.iterrows():
                try:
                    ts = pd.to_datetime(row[ts_col])
                    timeline_data.append({
                        'timestamp': ts,
                        'strategy': strategy_name.split('(')[0].strip()[:25],
                        'score': row[score_col],
                        'severity': 'High' if row[score_col] >= HIGH_SEVERITY_THRESHOLD else 'Medium' if row[score_col] >= MEDIUM_SEVERITY_THRESHOLD else 'Low'
                    })
                except (ValueError, KeyError, TypeError):
                    # Skip rows with invalid timestamps
                    pass
        
        if not timeline_data:
            print("⚠️ No timestamp data available in results. Strategies need timestamp columns for timeline analysis.")
            return
        
        timeline_df = pd.DataFrame(timeline_data)
        
        # Display summary statistics
        print("📊 Timeline Summary:")
        print(f"   • Total threat events: {len(timeline_df):,}")
        print(f"   • Date range: {timeline_df['timestamp'].min()} to {timeline_df['timestamp'].max()}")
        print(f"   • Strategies with timeline data: {timeline_df['strategy'].nunique()}")
        print()
        
        # Group by date and severity
        timeline_df['date'] = timeline_df['timestamp'].dt.date
        timeline_df['hour'] = timeline_df['timestamp'].dt.hour
        
        # Daily severity breakdown
        daily_summary = timeline_df.groupby(['date', 'severity']).size().unstack(fill_value=0)
        
        print("📅 Daily Threat Activity:")
        print("-" * 80)
        display(HTML(daily_summary.to_html(classes='table')))
        print()
        
        # Hourly heatmap if plotly available
        if HAS_PLOTLY:
            try:
                # Create hourly heatmap
                hourly_activity = timeline_df.groupby(['date', 'hour']).size().reset_index(name='count')
                
                # Pivot for heatmap
                heatmap_data = hourly_activity.pivot(index='date', columns='hour', values='count').fillna(0)
                
                fig = go.Figure(data=go.Heatmap(
                    z=heatmap_data.values,
                    x=[f"{h:02d}:00" for h in heatmap_data.columns],
                    y=[str(d) for d in heatmap_data.index],
                    colorscale='YlOrRd',
                    hoverongaps=False,
                    colorbar=dict(title="Threat Count")
                ))
                
                fig.update_layout(
                    title='Threat Activity Heatmap (by Date and Hour)',
                    xaxis_title='Hour of Day',
                    yaxis_title='Date',
                    height=400,
                    yaxis={'autorange': 'reversed'}
                )
                
                display(fig)
                print()
                
                # Strategy timeline
                strategy_timeline = timeline_df.groupby(['date', 'strategy', 'severity']).size().reset_index(name='count')
                
                fig2 = go.Figure()
                
                for severity in ['High', 'Medium', 'Low']:
                    severity_data = strategy_timeline[strategy_timeline['severity'] == severity]
                    
                    color = '#ef4444' if severity == 'High' else '#f59e0b' if severity == 'Medium' else '#10b981'
                    
                    for strategy in severity_data['strategy'].unique():
                        strat_data = severity_data[severity_data['strategy'] == strategy]
                        
                        fig2.add_trace(go.Scatter(
                            x=strat_data['date'],
                            y=strat_data['count'],
                            mode='lines+markers',
                            name=f"{strategy} ({severity})",
                            line=dict(color=color, width=2),
                            marker=dict(size=8),
                            stackgroup='one' if severity == 'High' else None
                        ))
                
                fig2.update_layout(
                    title='Threat Detection Timeline by Strategy',
                    xaxis_title='Date',
                    yaxis_title='Threat Count',
                    height=500,
                    hovermode='x unified'
                )
                
                display(fig2)
                
            except Exception as e:
                print(f"⚠️ Could not generate timeline charts: {e}")
        
        print()
        print("💡 Timeline Analysis Tips:")
        print("   • Look for unusual spikes in activity")
        print("   • Identify patterns in time-of-day attacks")
        print("   • Correlate timeline with known incidents")
        print("   • Use this to tune detection windows")
    
    def _show_threat_heatmap(self):
        """
        Display an IP address threat heatmap showing which IPs have the most/highest threats.
        """
        if not self.strategy_results:
            print("⚠️ No threat data available yet. Run some strategies first.")
            return
        
        print("=" * 80)
        print("🗺️  IP ADDRESS THREAT HEATMAP")
        print("=" * 80)
        print()
        
        # Collect IP and score data from all strategies
        ip_threat_data = []
        
        for strategy_name, result_data in self.strategy_results.items():
            df = result_data['dataframe']
            
            # Look for IP columns
            ip_cols = [col for col in df.columns if 'ip' in col.lower() or 'address' in col.lower()]
            if not ip_cols:
                continue
            
            ip_col = ip_cols[0]
            
            # Find score column
            score_cols = [col for col in df.columns if col.endswith('_score')]
            if not score_cols:
                continue
            
            score_col = score_cols[0]
            
            # Extract IP and score data
            for _, row in df.iterrows():
                ip = str(row[ip_col]) if pd.notna(row[ip_col]) else None
                score = row[score_col] if pd.notna(row[score_col]) else 0
                
                if ip and ip != 'Unknown':
                    ip_threat_data.append({
                        'ip': ip,
                        'strategy': strategy_name.split('(')[0].strip()[:25],
                        'score': score,
                        'severity': 'High' if score >= HIGH_SEVERITY_THRESHOLD else 'Medium' if score >= MEDIUM_SEVERITY_THRESHOLD else 'Low'
                    })
        
        if not ip_threat_data:
            print("⚠️ No IP address data available in results.")
            return
        
        ip_df = pd.DataFrame(ip_threat_data)
        
        # Aggregate by IP
        ip_summary = ip_df.groupby('ip').agg({
            'score': ['count', 'mean', 'max'],
            'strategy': lambda x: ', '.join(x.unique()[:3])
        }).reset_index()
        
        ip_summary.columns = ['IP Address', 'Threat Count', 'Avg Score', 'Max Score', 'Strategies']
        ip_summary = ip_summary.sort_values('Max Score', ascending=False)
        
        # Display top threatening IPs
        print("📊 Top 20 Most Threatening IP Addresses:")
        print("-" * 80)
        
        top_ips = ip_summary.head(20).copy()
        top_ips['Max Score'] = top_ips['Max Score'].apply(lambda x: f"{x:.1f}")
        top_ips['Avg Score'] = top_ips['Avg Score'].apply(lambda x: f"{x:.1f}")
        top_ips['Strategies'] = top_ips['Strategies'].apply(lambda x: x[:50] + '...' if len(x) > 50 else x)
        
        display(HTML(top_ips.to_html(index=False, escape=True, classes='table')))
        print()
        
        # Show severity breakdown
        severity_counts = ip_df.groupby('severity').size()
        print("🎯 Threat Severity Distribution:")
        for severity in ['High', 'Medium', 'Low']:
            count = severity_counts.get(severity, 0)
            emoji = '🔴' if severity == 'High' else '🟡' if severity == 'Medium' else '🟢'
            print(f"   {emoji} {severity}: {count:,} detections")
        print()
        
        # Visualization if plotly available
        if HAS_PLOTLY and len(ip_summary) > 0:
            try:
                # Create bubble chart: IP vs Strategy with size=count, color=max_score
                plot_data = ip_df[ip_df['ip'].isin(top_ips['IP Address'].head(15))]
                
                fig = go.Figure()
                
                for severity, color in [('High', '#ef4444'), ('Medium', '#f59e0b'), ('Low', '#10b981')]:
                    severity_data = plot_data[plot_data['severity'] == severity]
                    
                    if len(severity_data) > 0:
                        fig.add_trace(go.Scatter(
                            x=severity_data['ip'],
                            y=severity_data['strategy'],
                            mode='markers',
                            name=severity,
                            marker=dict(
                                size=severity_data['score'] / 3,
                                color=color,
                                line=dict(width=1, color='white'),
                                opacity=0.7
                            ),
                            text=severity_data['score'].apply(lambda x: f"Score: {x:.1f}"),
                            hovertemplate='<b>%{x}</b><br>Strategy: %{y}<br>%{text}<extra></extra>'
                        ))
                
                fig.update_layout(
                    title='IP Threat Heatmap: Distribution Across Strategies',
                    xaxis_title='IP Address',
                    yaxis_title='Detection Strategy',
                    height=600,
                    xaxis={'tickangle': -45},
                    showlegend=True,
                    legend=dict(title='Severity')
                )
                
                display(fig)
                print()
                
            except Exception as e:
                print(f"⚠️ Could not generate heatmap visualization: {e}")
        
        print("💡 Heatmap Analysis Tips:")
        print("   • Focus investigation on IPs with multiple high-severity detections")
        print("   • IPs appearing in many strategies suggest coordinated attack")
        print("   • Use correlation analysis for deeper IP relationship insights")
        print("   • Export top IPs for blocklist or SIEM integration")
        print()
    
    def _show_strategy_insights(self):
        """
        Display advanced insights comparing strategy effectiveness and coverage.
        """
        if not self.strategy_results:
            print("⚠️ No analysis results available yet. Run some strategies first.")
            return
        
        print("=" * 80)
        print("🎓 STRATEGY EFFECTIVENESS INSIGHTS")
        print("=" * 80)
        print()
        
        # Calculate metrics for each strategy
        insights = []
        
        for strategy_name, result_data in self.strategy_results.items():
            df = result_data['dataframe']
            
            if df.empty:
                continue
            
            # Find score column
            score_cols = [col for col in df.columns if col.endswith('_score')]
            if not score_cols:
                continue
            
            score_col = score_cols[0]
            
            # Calculate metrics
            total_detections = len(df)
            high_severity = len(df[df[score_col] >= HIGH_SEVERITY_THRESHOLD])
            medium_severity = len(df[(df[score_col] >= MEDIUM_SEVERITY_THRESHOLD) & (df[score_col] < HIGH_SEVERITY_THRESHOLD)])
            low_severity = len(df[df[score_col] < MEDIUM_SEVERITY_THRESHOLD])
            avg_score = df[score_col].mean()
            max_score = df[score_col].max()
            
            # Calculate coverage (unique IPs)
            ip_cols = [col for col in df.columns if 'ip' in col.lower() or 'address' in col.lower()]
            unique_ips = df[ip_cols[0]].nunique() if ip_cols else 0
            
            insights.append({
                'Strategy': strategy_name.split('(')[0].strip()[:30],
                'Total Findings': total_detections,
                'High Severity': high_severity,
                'Medium Severity': medium_severity,
                'Low Severity': low_severity,
                'Avg Score': f"{avg_score:.1f}",
                'Max Score': f"{max_score:.1f}",
                'Unique IPs': unique_ips,
                'Detection Rate': f"{(high_severity/total_detections*100):.1f}%" if total_detections > 0 else "0%"
            })
        
        if not insights:
            print("⚠️ No strategy data with scores available.")
            return
        
        insights_df = pd.DataFrame(insights)
        insights_df = insights_df.sort_values('High Severity', ascending=False)
        
        print("📊 Strategy Performance Comparison:")
        print("-" * 80)
        display(HTML(insights_df.to_html(index=False, escape=True, classes='table')))
        print()
        
        # Calculate overall statistics
        total_findings = insights_df['Total Findings'].sum()
        total_high = insights_df['High Severity'].sum()
        total_medium = insights_df['Medium Severity'].sum()
        total_low = insights_df['Low Severity'].sum()
        
        print("🎯 Overall Threat Landscape:")
        print(f"   • Total detections: {total_findings:,}")
        print(f"   • 🔴 High severity: {total_high:,} ({total_high/total_findings*100:.1f}%)")
        print(f"   • 🟡 Medium severity: {total_medium:,} ({total_medium/total_findings*100:.1f}%)")
        print(f"   • 🟢 Low severity: {total_low:,} ({total_low/total_findings*100:.1f}%)")
        print()
        
        # Identify most effective strategies
        most_effective = insights_df.nlargest(3, 'High Severity')
        print("🏆 Most Effective Strategies (by high-severity detections):")
        for i, row in enumerate(most_effective.itertuples(), 1):
            print(f"   {i}. {row.Strategy}: {row._2} high-severity threats")
        print()
        
        # Visualization if plotly available
        if HAS_PLOTLY and len(insights_df) > 0:
            try:
                # Create stacked bar chart of severity distribution
                fig = go.Figure()
                
                fig.add_trace(go.Bar(
                    name='High Severity',
                    x=insights_df['Strategy'],
                    y=insights_df['High Severity'],
                    marker_color='#ef4444'
                ))
                
                fig.add_trace(go.Bar(
                    name='Medium Severity',
                    x=insights_df['Strategy'],
                    y=insights_df['Medium Severity'],
                    marker_color='#f59e0b'
                ))
                
                fig.add_trace(go.Bar(
                    name='Low Severity',
                    x=insights_df['Strategy'],
                    y=insights_df['Low Severity'],
                    marker_color='#10b981'
                ))
                
                fig.update_layout(
                    title='Strategy Effectiveness: Severity Distribution',
                    xaxis_title='Strategy',
                    yaxis_title='Number of Detections',
                    barmode='stack',
                    height=500,
                    xaxis={'tickangle': -45},
                    legend=dict(title='Severity Level')
                )
                
                display(fig)
                print()
                
            except Exception as e:
                print(f"⚠️ Could not generate insights visualization: {e}")
        
        print("💡 Strategic Insights:")
        print("   • Strategies with many high-severity findings need priority attention")
        print("   • Low detection rates may indicate clean environment or need tuning")
        print("   • Compare unique IP counts to identify targeted vs. broad attacks")
        print("   • Use this to prioritize which strategies to run regularly")
        print()
    
    def _show_threat_overview_dashboard(self):
        """
        Display a comprehensive overview of all strategies and their findings at a glance.
        """
        if not self.strategy_results:
            print("⚠️ No threat data available yet. Run some strategies first.")
            return
        
        print("=" * 80)
        print("🎯 COMPREHENSIVE THREAT OVERVIEW DASHBOARD")
        print("=" * 80)
        print()
        
        # Collect comprehensive statistics
        overview_data = []
        total_threats = 0
        total_critical = 0
        total_high = 0
        total_medium = 0
        total_low = 0
        all_ips = set()
        
        for strategy_name, result_data in self.strategy_results.items():
            df = result_data['dataframe']
            
            if df.empty:
                continue
            
            # Find score column
            score_col = None
            for col in df.columns:
                if 'score' in col.lower():
                    score_col = col
                    break
            
            if not score_col:
                continue
            
            # Count by severity
            critical = len(df[df[score_col] >= CRITICAL_SEVERITY_THRESHOLD])
            high = len(df[(df[score_col] >= HIGH_SEVERITY_THRESHOLD) & (df[score_col] < CRITICAL_SEVERITY_THRESHOLD)])
            medium = len(df[(df[score_col] >= MEDIUM_SEVERITY_THRESHOLD) & (df[score_col] < HIGH_SEVERITY_THRESHOLD)])
            low = len(df[df[score_col] < MEDIUM_SEVERITY_THRESHOLD])
            
            total_threats += len(df)
            total_critical += critical
            total_high += high
            total_medium += medium
            total_low += low
            
            # Collect unique IPs
            for col in df.columns:
                if 'ip' in col.lower() and col not in ['destination_ip', 'dest_ip', 'dst_ip']:
                    ips = df[col].dropna().unique()
                    all_ips.update(str(ip) for ip in ips)
            
            # Average score
            avg_score = df[score_col].mean()
            max_score = df[score_col].max()
            
            overview_data.append({
                'Strategy': strategy_name,
                'Total': len(df),
                '🔴 Critical': critical,
                '🟠 High': high,
                '🟡 Medium': medium,
                '🟢 Low': low,
                'Avg Score': round(avg_score, 1),
                'Max Score': int(max_score)
            })
        
        if not overview_data:
            print("⚠️ No scoreable data found in results.")
            return
        
        # Create DataFrame and sort by total threats
        overview_df = pd.DataFrame(overview_data)
        overview_df = overview_df.sort_values('Total', ascending=False)
        
        # Display summary statistics
        print("📊 OVERALL THREAT LANDSCAPE:")
        print(f"   • Total detections across all strategies: {total_threats:,}")
        print(f"   • 🔴 Critical threats (≥90): {total_critical:,}")
        print(f"   • 🟠 High severity (75-89): {total_high:,}")
        print(f"   • 🟡 Medium severity (50-74): {total_medium:,}")
        print(f"   • 🟢 Low severity (<50): {total_low:,}")
        print(f"   • Unique source IPs flagged: {len(all_ips):,}")
        print()
        
        # Risk assessment
        critical_pct = (total_critical / total_threats * 100) if total_threats > 0 else 0
        if critical_pct > 10:
            print("⚠️  HIGH RISK: >10% of threats are critical. Immediate action required!")
        elif critical_pct > 5:
            print("⚠️  ELEVATED RISK: 5-10% critical threats. Prioritize investigation.")
        else:
            print("✅ MODERATE RISK: <5% critical threats. Continue monitoring.")
        print()
        
        # Display strategy breakdown
        print("📋 STRATEGY-BY-STRATEGY BREAKDOWN:")
        print()
        
        # Format and display the table
        for idx, row in overview_df.iterrows():
            total = row['Total']
            print(f"🔍 {row['Strategy']}")
            print(f"   Total: {total:,} | Critical: {row['🔴 Critical']} | High: {row['🟠 High']} | "
                  f"Medium: {row['🟡 Medium']} | Low: {row['🟢 Low']}")
            print(f"   Avg Score: {row['Avg Score']} | Max Score: {row['Max Score']}")
            
            # Risk indicator
            if row['🔴 Critical'] > 0:
                print("   ⚠️  CRITICAL findings detected - investigate immediately!")
            elif row['🟠 High'] > 10:
                print("   ⚠️  Multiple high-severity findings - prioritize review")
            
            print()
        
        # Top 5 most concerning strategies
        print("🏆 TOP 5 MOST CONCERNING STRATEGIES:")
        top5 = overview_df.nlargest(5, '🔴 Critical')
        for i, (idx, row) in enumerate(top5.iterrows(), 1):
            print(f"   {i}. {row['Strategy']}: {row['🔴 Critical']} critical + {row['🟠 High']} high-severity threats")
        print()
        
        # Visualization if available
        if HAS_PLOTLY and len(overview_df) > 0:
            try:
                # Create a comprehensive dashboard with multiple visualizations
                # Stacked bar chart of severity distribution
                fig1 = go.Figure()
                
                fig1.add_trace(go.Bar(
                    name='Critical (≥90)',
                    x=overview_df['Strategy'],
                    y=overview_df['🔴 Critical'],
                    marker_color='#dc2626'
                ))
                
                fig1.add_trace(go.Bar(
                    name='High (75-89)',
                    x=overview_df['Strategy'],
                    y=overview_df['🟠 High'],
                    marker_color='#ea580c'
                ))
                
                fig1.add_trace(go.Bar(
                    name='Medium (50-74)',
                    x=overview_df['Strategy'],
                    y=overview_df['🟡 Medium'],
                    marker_color='#f59e0b'
                ))
                
                fig1.add_trace(go.Bar(
                    name='Low (<50)',
                    x=overview_df['Strategy'],
                    y=overview_df['🟢 Low'],
                    marker_color='#10b981'
                ))
                
                fig1.update_layout(
                    title='Threat Distribution by Strategy and Severity',
                    xaxis_title='Strategy',
                    yaxis_title='Number of Threats',
                    barmode='stack',
                    height=500,
                    xaxis={'tickangle': -45}
                )
                
                display(fig1)
                
                # Pie chart of overall severity distribution
                fig2 = go.Figure(go.Pie(
                    labels=['Critical', 'High', 'Medium', 'Low'],
                    values=[total_critical, total_high, total_medium, total_low],
                    marker=dict(colors=['#dc2626', '#ea580c', '#f59e0b', '#10b981']),
                    textinfo='label+percent+value',
                    hovertemplate='<b>%{label}</b><br>Count: %{value}<br>Percentage: %{percent}<extra></extra>'
                ))
                
                fig2.update_layout(
                    title='Overall Threat Severity Distribution',
                    height=400
                )
                
                display(fig2)
                
                # Scatter plot: Avg Score vs Total Threats
                fig3 = go.Figure(go.Scatter(
                    x=overview_df['Avg Score'],
                    y=overview_df['Total'],
                    mode='markers+text',
                    marker=dict(
                        size=overview_df['🔴 Critical'] * 5 + 10,
                        color=overview_df['Max Score'],
                        colorscale='Reds',
                        showscale=True,
                        colorbar=dict(title="Max Score"),
                        line=dict(width=1, color='darkred')
                    ),
                    text=overview_df['Strategy'],
                    textposition='top center',
                    hovertemplate='<b>%{text}</b><br>Avg Score: %{x:.1f}<br>Total: %{y}<extra></extra>'
                ))
                
                fig3.update_layout(
                    title='Strategy Effectiveness: Average Score vs Detection Volume',
                    xaxis_title='Average Threat Score',
                    yaxis_title='Total Detections',
                    height=500
                )
                
                display(fig3)
                
            except Exception as e:
                print(f"⚠️ Could not generate visualizations: {e}")
        
        print()
        print("💡 Dashboard Tips:")
        print("   • Focus on strategies with critical findings first")
        print("   • Investigate IPs appearing in multiple strategies using Correlations")
        print("   • Use Quick Triage to see all critical threats in one place")
        print("   • Export findings for further analysis or reporting")
        print()
    
    def _show_smart_recommendations(self):
        """
        Provide intelligent recommendations for next steps based on current findings.
        """
        if not self.strategy_results:
            print("⚠️ No analysis results yet. Run some strategies first to get recommendations.")
            return
        
        print("=" * 80)
        print("🎯 SMART RECOMMENDATIONS")
        print("=" * 80)
        print()
        
        # Analyze what's been detected so far
        high_severity_strategies = []
        medium_severity_strategies = []
        run_strategies = set()
        
        for strategy_name, result_data in self.strategy_results.items():
            df = result_data['dataframe']
            run_strategies.add(strategy_name)
            
            # Find score column
            score_cols = [col for col in df.columns if col.endswith('_score')]
            if score_cols:
                score_col = score_cols[0]
                high_count = len(df[df[score_col] >= HIGH_SEVERITY_THRESHOLD])
                medium_count = len(df[(df[score_col] >= MEDIUM_SEVERITY_THRESHOLD) & (df[score_col] < HIGH_SEVERITY_THRESHOLD)])
                
                if high_count > 0:
                    high_severity_strategies.append((strategy_name, high_count))
                if medium_count > 0:
                    medium_severity_strategies.append((strategy_name, medium_count))
        
        # Recommendation logic based on detection patterns
        recommendations = []
        
        # Check which strategies have been run
        all_strategy_names = [s.name for s in self.strategies]
        unrun_strategies = [s for s in all_strategy_names if s not in run_strategies]
        
        # Provide context-aware recommendations
        if any('Beacon' in s for s in high_severity_strategies):
            recommendations.append({
                'priority': 'HIGH',
                'strategy': 'Port Scan Detector or Lateral Movement Detector',
                'reason': 'Beaconing detected - check for reconnaissance and lateral movement',
                'icon': '🔴'
            })
        
        if any('Privilege Escalation' in s[0] for s in high_severity_strategies):
            recommendations.append({
                'priority': 'HIGH',
                'strategy': 'Credential Dumping Detector',
                'reason': 'Privilege escalation detected - check for credential theft',
                'icon': '🔴'
            })
        
        if any('Credential Dumping' in s[0] for s in high_severity_strategies):
            recommendations.append({
                'priority': 'HIGH',
                'strategy': 'Lateral Movement Detector or Account Takeover Detector',
                'reason': 'Credentials compromised - check for account misuse',
                'icon': '🔴'
            })
        
        if any('Webshell' in s[0] for s in high_severity_strategies):
            recommendations.append({
                'priority': 'HIGH',
                'strategy': 'Data Staging Detector or Exfiltration Monitor',
                'reason': 'Web shell detected - check for data theft preparation',
                'icon': '🔴'
            })
        
        if any('Ransomware' in s[0] for s in high_severity_strategies):
            recommendations.append({
                'priority': 'CRITICAL',
                'strategy': 'Immediately isolate affected systems',
                'reason': 'Ransomware indicators - immediate incident response required',
                'icon': '🚨'
            })
        
        if any('Exfiltration' in s for s in high_severity_strategies) or any('Data Staging' in s[0] for s in high_severity_strategies):
            recommendations.append({
                'priority': 'HIGH',
                'strategy': 'Shadow IT Detector',
                'reason': 'Data movement detected - check for unauthorized cloud uploads',
                'icon': '🔴'
            })
        
        # General recommendations based on coverage
        if len(run_strategies) < 5:
            recommendations.append({
                'priority': 'MEDIUM',
                'strategy': 'Run more detection strategies',
                'reason': 'Increase coverage by running additional threat hunting strategies',
                'icon': '🟡'
            })
        
        if unrun_strategies:
            top_unrun = unrun_strategies[:3]
            recommendations.append({
                'priority': 'LOW',
                'strategy': ', '.join([s.split('(')[0].strip() for s in top_unrun]),
                'reason': 'Consider running these strategies for comprehensive coverage',
                'icon': '🟢'
            })
        
        # Display recommendations
        if recommendations:
            for rec in recommendations:
                priority_color = {
                    'CRITICAL': '#dc2626',
                    'HIGH': '#f59e0b',
                    'MEDIUM': '#3b82f6',
                    'LOW': '#10b981'
                }
                
                rec_html = f"""
                <div style="background: {priority_color.get(rec['priority'], '#6366f1')}; 
                            color: white; padding: 16px; border-radius: 12px; margin: 10px 0;
                            box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                    <div style="font-size: 1.2em; font-weight: bold; margin-bottom: 8px;">
                        {rec['icon']} {rec['priority']} PRIORITY
                    </div>
                    <div style="font-size: 1.1em; margin-bottom: 6px;">
                        <strong>Recommended Action:</strong> {rec['strategy']}
                    </div>
                    <div style="opacity: 0.95;">
                        <strong>Reason:</strong> {rec['reason']}
                    </div>
                </div>
                """
                display(HTML(rec_html))
        else:
            print("✅ No specific recommendations at this time.")
            print("   Continue monitoring with periodic strategy runs.")
        
        print()
        print("💡 Best Practices:")
        print("   • Follow high-priority recommendations first")
        print("   • Run related strategies to understand the full attack chain")
        print("   • Use correlation analysis to connect findings")
        print("   • Document your investigation path for reporting")
    
    def _on_load_table(self, button, tab_index: int):
        """
        Load table schema when button is pressed.
        
        Args:
            button: Button widget that triggered this callback
            tab_index: Index of the tab
        """
        tab_data = self.strategy_tab_contents[tab_index]
        current_table = tab_data['table_dropdown'].value
        
        if not current_table or current_table in ['No tables available', 'Error loading tables', 'No matching tables']:
            with tab_data['output_widget']:
                clear_output(wait=True)
                print("⚠️ Please select a valid table.")
            return
        
        # Get column information using DESCRIBE
        with tab_data['output_widget']:
            clear_output(wait=True)
            print(f"📥 Loading schema for {current_table}...")
        
        tab_data['available_columns'] = self._get_table_columns(current_table)
        
        # Build column mapping UI
        self._build_column_mappings(tab_index)
        
        with tab_data['output_widget']:
            clear_output(wait=True)
            print(f"✅ Loaded {len(tab_data['available_columns'])} columns from {current_table}")
            print("Configure column mappings above and click 'Run Analysis' when ready.")
    
    def _display_summary_stats(self, df: pd.DataFrame, strategy: HuntStrategy):
        """
        Display summary statistics dashboard for analysis results.
        
        Args:
            df: Results DataFrame
            strategy: The strategy that produced these results
        """
        # Identify score columns (typically end with '_score')
        score_cols = [col for col in df.columns if col.endswith('_score')]
        
        # Calculate basic stats
        total_results = len(df)
        
        # Build summary HTML with enhanced modern design
        summary_html = f"""
        <div style="background: {GRADIENT_BLUE_PURPLE}; color: white; padding: 24px; border-radius: 16px; margin: 15px 0; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
            <h3 style="margin-top: 0; font-size: 1.5em; display: flex; align-items: center; gap: 8px;">📊 Analysis Summary</h3>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-top: 20px;">
                <div style="{CSS_CARD_TRANSLUCENT}">
                    <div style="font-size: 2.5em; font-weight: bold; margin-bottom: 4px;">{total_results}</div>
                    <div style="{CSS_TEXT_MUTED}">Suspicious Activities</div>
                </div>
        """
        
        # Add severity breakdown if score columns exist
        if score_cols:
            score_col = score_cols[0]  # Use first score column
            high_severity = len(df[df[score_col] >= HIGH_SEVERITY_THRESHOLD])
            medium_severity = len(df[(df[score_col] >= MEDIUM_SEVERITY_THRESHOLD) & (df[score_col] < HIGH_SEVERITY_THRESHOLD)])
            max_score = df[score_col].max()
            
            summary_html += f"""
                <div style="{CSS_CARD_TRANSLUCENT}">
                    <div style="font-size: 2.5em; font-weight: bold; color: #fca5a5; margin-bottom: 4px;">🔴 {high_severity}</div>
                    <div style="{CSS_TEXT_MUTED}">High Severity (≥75)</div>
                </div>
                <div style="{CSS_CARD_TRANSLUCENT}">
                    <div style="font-size: 2.5em; font-weight: bold; color: #fcd34d; margin-bottom: 4px;">🟡 {medium_severity}</div>
                    <div style="{CSS_TEXT_MUTED}">Medium Severity (50-74)</div>
                </div>
                <div style="{CSS_CARD_TRANSLUCENT}">
                    <div style="font-size: 2.5em; font-weight: bold; margin-bottom: 4px;">{df[score_col].mean():.1f}</div>
                    <div style="{CSS_TEXT_MUTED}">Average Score</div>
                </div>
                <div style="{CSS_CARD_TRANSLUCENT}">
                    <div style="font-size: 2.5em; font-weight: bold; color: {'#fca5a5' if max_score >= HIGH_SEVERITY_THRESHOLD else '#fcd34d' if max_score >= MEDIUM_SEVERITY_THRESHOLD else '#86efac'}; margin-bottom: 4px;">{max_score:.1f}</div>
                    <div style="{CSS_TEXT_MUTED}">Highest Score</div>
                </div>
            """
        
        summary_html += """
            </div>
        </div>
        """
        
        display(HTML(summary_html))
        
        # Add score distribution visualization if plotly is available and we have scores
        if score_cols and HAS_PLOTLY:
            try:
                score_col = score_cols[0]
                import plotly.graph_objects as go
                
                # Create histogram of score distribution
                fig = go.Figure()
                
                fig.add_trace(go.Histogram(
                    x=df[score_col],
                    nbinsx=20,
                    marker=dict(
                        color=df[score_col],
                        colorscale='RdYlGn_r',  # Red (high) to Green (low)
                        showscale=False,
                        line=dict(color='white', width=1)
                    ),
                    name='Score Distribution'
                ))
                
                # Add vertical lines for thresholds
                fig.add_vline(x=75, line_dash="dash", line_color="red", 
                             annotation_text="High (≥75)", annotation_position="top right")
                fig.add_vline(x=50, line_dash="dash", line_color="orange",
                             annotation_text="Medium (≥50)", annotation_position="top right")
                
                fig.update_layout(
                    title=f"Threat Score Distribution - {strategy.name}",
                    xaxis_title="Threat Score",
                    yaxis_title="Count",
                    showlegend=False,
                    height=350,
                    margin=dict(l=50, r=50, t=50, b=50),
                    plot_bgcolor='rgba(0,0,0,0)',
                    paper_bgcolor='rgba(0,0,0,0)'
                )
                
                display(fig)
            except Exception:
                # Silently fail if visualization doesn't work
                pass
        
        print()
    
    def _display_collapsible_explanations(self, explanations: dict, df: pd.DataFrame):
        """
        Display column explanations in a collapsible widget.
        
        Args:
            explanations: Dictionary of column explanations
            df: Results DataFrame to filter relevant columns
        """
        # Filter to only show explanations for columns in the result
        relevant_explanations = {k: v for k, v in explanations.items() if k in df.columns}
        
        if not relevant_explanations:
            return
        
        # Build explanations HTML
        explanations_html = "<div style='padding: 10px; background: #f8f9fa; border-radius: 5px; margin: 10px 0;'>"
        for col_name, explanation in relevant_explanations.items():
            explanations_html += f"""
            <div style="margin: 8px 0; padding: 8px; background: white; border-left: 3px solid #007bff; border-radius: 3px;">
                <b style="color: #007bff;">{col_name}:</b> 
                <span style="color: #495057;">{explanation}</span>
            </div>
            """
        explanations_html += "</div>"
        
        # Create accordion widget
        accordion = widgets.Accordion(children=[widgets.HTML(value=explanations_html)])
        accordion.set_title(0, '📖 Column Explanations (click to expand)')
        accordion.selected_index = None  # Start collapsed
        
        display(accordion)
        print()
    
    def _display_sortable_results(self, df: pd.DataFrame, strategy_name: str = "Results", rows_per_page: int = 100):
        """
        Display results with sorting, pagination, filtering, and export controls using ipywidgets.
        
        Args:
            df: DataFrame to display
            strategy_name: Name of the strategy for export filename
            rows_per_page: Number of rows to display per page
        """
        # Store the full dataframe for pagination
        full_df = df
        
        # Identify score column for filtering
        score_cols = [col for col in df.columns if col.endswith('_score')]
        has_score_column = len(score_cols) > 0
        score_col = score_cols[0] if has_score_column else None
        
        # State variables for pagination, sorting, and filtering
        current_page = {'value': 0}
        current_sort = {'column': '(unsorted)', 'ascending': False}
        current_filter = {'level': 'All'}
        current_search = {'text': '', 'regex': False}
        cached_sorted_df = {'df': full_df, 'total_pages': 1}  # Cache for sorted DataFrame
        
        # Create text search box with regex support
        search_box = widgets.Text(
            placeholder='Search in results... (supports regex with .* patterns)',
            description='🔍 Search:',
            style={'description_width': 'initial'},
            layout=widgets.Layout(width='450px')
        )
        
        regex_checkbox = widgets.Checkbox(
            value=False,
            description='Regex Mode',
            tooltip='Enable regex pattern matching',
            layout=widgets.Layout(width='120px')
        )
        
        clear_search_button = widgets.Button(
            description='Clear',
            button_style='',
            layout=widgets.Layout(width='80px')
        )
        
        # Create sorting controls
        sort_column = widgets.Dropdown(
            options=['(unsorted)'] + list(full_df.columns),
            value='(unsorted)',
            description='Sort by:',
            style={'description_width': 'initial'}
        )
        
        sort_order = widgets.ToggleButtons(
            options=['Ascending', 'Descending'],
            value='Descending',
            description='Order:',
            button_style='info',
            style={'description_width': 'initial'}
        )
        
        # Create severity filter buttons (only if score column exists)
        filter_buttons = None
        if has_score_column:
            filter_buttons = widgets.ToggleButtons(
                options=['All', 'High (≥75)', 'Medium (50-74)', 'Low (<50)'],
                value='All',
                description='Filter:',
                button_style='',
                tooltips=['Show all results', 'Show only high severity', 'Show only medium severity', 'Show only low severity'],
                style={'description_width': 'initial', 'button_width': 'auto'}
            )
        
        # Create pagination controls
        prev_button = widgets.Button(
            description='◀ Previous',
            button_style='primary',
            disabled=True,
            layout=widgets.Layout(width='120px')
        )
        
        next_button = widgets.Button(
            description='Next ▶',
            button_style='primary',
            layout=widgets.Layout(width='120px')
        )
        
        page_info = widgets.HTML(value='')
        
        # Create export buttons
        export_csv_button = widgets.Button(
            description='📥 Export CSV',
            button_style='success',
            icon='download',
            layout=widgets.Layout(width='150px')
        )
        
        export_json_button = widgets.Button(
            description='📦 Export JSON',
            button_style='info',
            icon='download',
            tooltip='Export as JSON for SIEM integration',
            layout=widgets.Layout(width='150px')
        )
        
        export_output = widgets.Output()
        
        # Create output area for the table
        table_output = widgets.Output()
        
        def apply_text_search(df, search_term, use_regex):
            """Apply text search to dataframe (helper to avoid duplication)."""
            mask = pd.Series([False] * len(df), index=df.index)
            search_term_lower = search_term.lower()
            
            for col in df.columns:
                if use_regex:
                    # Regex search (case-insensitive)
                    mask |= df[col].astype(str).str.contains(search_term, na=False, regex=True, case=False)
                else:
                    # Plain text search (case-insensitive)
                    mask |= df[col].astype(str).str.lower().str.contains(search_term_lower, na=False, regex=False)
            return df[mask]
        
        def get_sorted_df():
            """Get the dataframe with current sorting and filtering applied (cached)."""
            # First apply text search if present
            if current_search['text']:
                search_term = current_search['text']
                use_regex = current_search.get('regex', False)
                
                try:
                    filtered_df = apply_text_search(full_df, search_term, use_regex)
                except re.error as e:
                    # Invalid regex pattern, fall back to plain text search
                    print(f"⚠️ Invalid regex pattern: {e}. Using plain text search.")
                    filtered_df = apply_text_search(full_df, search_term, use_regex=False)
            else:
                filtered_df = full_df
            
            # Then apply severity filtering
            if has_score_column and current_filter['level'] != 'All':
                if current_filter['level'] == 'High (≥75)':
                    filtered_df = filtered_df[filtered_df[score_col] >= HIGH_SEVERITY_THRESHOLD]
                elif current_filter['level'] == 'Medium (50-74)':
                    filtered_df = filtered_df[(filtered_df[score_col] >= MEDIUM_SEVERITY_THRESHOLD) & (filtered_df[score_col] < HIGH_SEVERITY_THRESHOLD)]
                elif current_filter['level'] == 'Low (<50)':
                    filtered_df = filtered_df[filtered_df[score_col] < MEDIUM_SEVERITY_THRESHOLD]
            
            # Then apply sorting
            if current_sort['column'] != '(unsorted)':
                sorted_df = filtered_df.sort_values(
                    by=current_sort['column'],
                    ascending=current_sort['ascending']
                )
            else:
                sorted_df = filtered_df
            
            # Update cache
            total_rows = len(sorted_df)
            total_pages = (total_rows + rows_per_page - 1) // rows_per_page
            cached_sorted_df['df'] = sorted_df
            cached_sorted_df['total_pages'] = total_pages
            
            return sorted_df
        
        def update_table():
            """Update the displayed table based on current page and sort settings."""
            sorted_df = cached_sorted_df['df']
            total_rows = len(sorted_df)
            total_pages = cached_sorted_df['total_pages']
            
            # Calculate start and end indices for current page
            start_idx = current_page['value'] * rows_per_page
            end_idx = min(start_idx + rows_per_page, total_rows)
            
            # Get the page data
            page_df = sorted_df.iloc[start_idx:end_idx].copy()
            
            # Add color-coded styling to table based on score if available
            if has_score_column and score_col in page_df.columns:
                # Create styled HTML table with color-coded rows and modern design
                table_html = '<table border="1" class="dataframe" style="border-collapse: collapse; width: 100%; box-shadow: 0 2px 8px rgba(0,0,0,0.1); border-radius: 8px; overflow: hidden;">\n'
                table_html += f'  <thead>\n    <tr style="text-align: right; background: {GRADIENT_BLUE_PURPLE}; color: white; font-weight: bold;">\n'
                for col in page_df.columns:
                    table_html += f'      <th style="padding: 8px; border: 1px solid #ddd;">{col}</th>\n'
                table_html += '    </tr>\n  </thead>\n  <tbody>\n'
                
                for idx, row in page_df.iterrows():
                    score = row[score_col]
                    # Color code based on severity with enhanced modern styling
                    if score >= HIGH_SEVERITY_THRESHOLD:
                        bg_color = COLOR_HIGH_SEVERITY_BG
                        badge = f'<span style="background: {COLOR_HIGH_SEVERITY_BADGE}; color: white; padding: 4px 10px; border-radius: 12px; font-size: 0.75em; font-weight: bold; letter-spacing: 0.5px; box-shadow: 0 1px 3px rgba(0,0,0,0.12); display: inline-block;">🔴 HIGH</span>'
                    elif score >= MEDIUM_SEVERITY_THRESHOLD:
                        bg_color = COLOR_MEDIUM_SEVERITY_BG
                        badge = f'<span style="background: {COLOR_MEDIUM_SEVERITY_BADGE}; color: white; padding: 4px 10px; border-radius: 12px; font-size: 0.75em; font-weight: bold; letter-spacing: 0.5px; box-shadow: 0 1px 3px rgba(0,0,0,0.12); display: inline-block;">🟡 MED</span>'
                    else:
                        bg_color = COLOR_LOW_SEVERITY_BG
                        badge = f'<span style="background: {COLOR_LOW_SEVERITY_BADGE}; color: white; padding: 4px 10px; border-radius: 12px; font-size: 0.75em; font-weight: bold; letter-spacing: 0.5px; box-shadow: 0 1px 3px rgba(0,0,0,0.12); display: inline-block;">🟢 LOW</span>'
                    
                    table_html += f'    <tr style="background-color: {bg_color};">\n'
                    for col in page_df.columns:
                        value = row[col]
                        # Format score column with badge
                        if col == score_col:
                            table_html += f'      <td style="padding: 8px; border: 1px solid #ddd;">{value:.1f} {badge}</td>\n'
                        else:
                            table_html += f'      <td style="padding: 8px; border: 1px solid #ddd;">{value}</td>\n'
                    table_html += '    </tr>\n'
                
                table_html += '  </tbody>\n</table>'
                
                # Update table display with styled HTML
                with table_output:
                    clear_output(wait=True)
                    display(HTML(table_html))
            else:
                # No score column, use standard table
                with table_output:
                    clear_output(wait=True)
                    display(HTML(page_df.to_html(index=False)))
            
            # Update page info
            page_info.value = f"<b>Page {current_page['value'] + 1} of {total_pages}</b> (Rows {start_idx + 1}-{end_idx} of {total_rows})"
            
            # Update button states
            prev_button.disabled = (current_page['value'] == 0)
            next_button.disabled = (current_page['value'] >= total_pages - 1)
        
        def on_sort_change(change):
            """Handle sorting changes."""
            current_sort['column'] = sort_column.value
            current_sort['ascending'] = (sort_order.value == 'Ascending')
            current_page['value'] = 0  # Reset to first page when sorting changes
            get_sorted_df()  # Refresh cache
            update_table()
        
        def on_filter_change(change):
            """Handle filter changes."""
            current_filter['level'] = filter_buttons.value
            current_page['value'] = 0  # Reset to first page when filtering changes
            get_sorted_df()  # Refresh cache
            update_table()
        
        def on_prev_click(b):
            """Handle previous button click."""
            if current_page['value'] > 0:
                current_page['value'] -= 1
                update_table()
        
        def on_next_click(b):
            """Handle next button click."""
            if current_page['value'] < cached_sorted_df['total_pages'] - 1:
                current_page['value'] += 1
                update_table()
        
        def on_search_change(change):
            """Handle search text changes."""
            current_search['text'] = search_box.value
            current_page['value'] = 0  # Reset to first page when searching
            get_sorted_df()  # Refresh cache
            update_table()
        
        def on_regex_change(change):
            """Handle regex checkbox changes."""
            current_search['regex'] = regex_checkbox.value
            if current_search['text']:  # Only refresh if there's text to search
                current_page['value'] = 0
                get_sorted_df()
                update_table()
        
        def on_clear_search_click(b):
            """Handle clear search button click."""
            search_box.value = ''
            regex_checkbox.value = False
            current_search['text'] = ''
            current_search['regex'] = False
            current_page['value'] = 0
            get_sorted_df()
            update_table()
        
        def on_export_csv_click(b):
            """Handle CSV export button click."""
            with export_output:
                clear_output(wait=True)
                sorted_df = cached_sorted_df['df']
                success, filename, error = self._export_dataframe(sorted_df, strategy_name, 'csv')
                if success:
                    print(f"✅ Exported {len(sorted_df)} rows to {filename}")
                else:
                    print(f"❌ Export failed: {error}")
        
        def on_export_json_click(b):
            """Handle JSON export button click."""
            with export_output:
                clear_output(wait=True)
                sorted_df = cached_sorted_df['df']
                success, filename, error = self._export_dataframe(sorted_df, strategy_name, 'json')
                if success:
                    print(f"✅ Exported {len(sorted_df)} rows to {filename}")
                    print("💡 JSON format is ideal for SIEM integration, API ingestion, or programmatic analysis")
                else:
                    print(f"❌ Export failed: {error}")
        
        # Attach observers and handlers
        search_box.observe(on_search_change, names='value')
        regex_checkbox.observe(on_regex_change, names='value')
        clear_search_button.on_click(on_clear_search_click)
        sort_column.observe(on_sort_change, names='value')
        sort_order.observe(on_sort_change, names='value')
        if filter_buttons:
            filter_buttons.observe(on_filter_change, names='value')
        prev_button.on_click(on_prev_click)
        next_button.on_click(on_next_click)
        export_csv_button.on_click(on_export_csv_click)
        export_json_button.on_click(on_export_json_click)
        
        # Initial display
        update_table()
        
        # Create the UI layout
        sort_controls = widgets.HBox([sort_column, sort_order, export_csv_button, export_json_button])
        pagination_controls = widgets.HBox([prev_button, page_info, next_button], 
                                          layout=widgets.Layout(justify_content='center'))
        
        # Build the results UI components
        ui_components = [
            widgets.HTML("<h4>📊 Results</h4>"),
        ]
        
        # Add search box with regex support
        ui_components.append(widgets.HTML("<div style='margin: 10px 0;'><b>🔍 Text Search & Filters:</b></div>"))
        ui_components.append(widgets.HBox([search_box, regex_checkbox, clear_search_button]))
        
        # Add filter buttons if score column exists
        if filter_buttons:
            ui_components.append(widgets.HTML("<div style='margin: 10px 0 5px 0;'><b>Severity Filter:</b></div>"))
            ui_components.append(filter_buttons)
        
        ui_components.extend([
            widgets.HTML("<div style='margin: 10px 0 5px 0;'><b>Sort & Export:</b></div>"),
            sort_controls,
            export_output,
            pagination_controls,
            table_output,
            pagination_controls  # Show pagination at bottom too for convenience
        ])
        
        sortable_table = widgets.VBox(ui_components)
        
        display(sortable_table)
    
    def _export_dataframe(self, df: pd.DataFrame, strategy_name: str, export_format: str = 'csv') -> tuple:
        """
        Export a DataFrame to file with standardized naming and error handling.
        Consolidates duplicate export logic used across multiple methods.
        
        Args:
            df: DataFrame to export
            strategy_name: Name of strategy (used for filename)
            export_format: 'csv' or 'json'
        
        Returns:
            tuple: (success: bool, filename: str, error_msg: str or None)
        """
        try:
            timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            safe_name = re.sub(r'[^\w\s-]', '', strategy_name).strip().replace(' ', '_')
            
            if export_format == 'json':
                filename = f"{safe_name}_{timestamp}.json"
                df.to_json(filename, orient='records', date_format='iso', indent=2)
            else:  # default to CSV
                filename = f"{safe_name}_{timestamp}.csv"
                df.to_csv(filename, index=False)
            
            return (True, filename, None)
        except Exception as e:
            return (False, '', str(e))
    
    def _sanitize_identifier(self, identifier: str) -> str:
        """
        Sanitize SQL identifier to prevent SQL injection.
        
        Args:
            identifier: Table or column name (may include nested paths like 'field.subfield')
        
        Returns:
            Sanitized identifier
        
        Raises:
            ValueError: If identifier contains invalid characters
        
        Note:
            Dots are allowed for schema-qualified names (e.g., schema.table)
            and nested field access (e.g., struct_field.nested_field).
            Since table/column names come from information_schema and DESCRIBE
            queries (system-controlled), the risk of malicious input is minimal.
            User cannot directly input these values - they select from dropdowns.
        """
        # Allow alphanumeric, underscore, and dot (for schema.table and nested fields)
        if not re.match(r'^[a-zA-Z0-9_\.]+$', identifier):
            raise ValueError(f"Invalid identifier: {identifier}")
        return identifier
    
    def _get_table_columns(self, table_name: str) -> list:
        """
        Get columns for a specific table using DESCRIBE.
        
        Args:
            table_name: Name of the table
        
        Returns:
            List of column names including nested fields
        """
        try:
            # Sanitize table name to prevent SQL injection
            sanitized_table = self._sanitize_identifier(table_name)
            query = f"DESCRIBE ionic.events.{sanitized_table}"
            df = isf.run_query(query)
            
            if df is not None and not df.empty:
                columns = []
                type_col = None
                
                # DESCRIBE returns column info - try common column names
                # Most SQL systems use 'Column', 'column_name', or 'Field'
                for col_name in ['Column', 'column_name', 'Field', 'field']:
                    if col_name in df.columns:
                        columns = df[col_name].tolist()
                        break
                
                # If no standard column found, use first column
                if not columns:
                    columns = df.iloc[:, 0].tolist()
                
                # Try to find Type column for nested field detection
                for type_name in ['Type', 'type', 'Data Type', 'data_type']:
                    if type_name in df.columns:
                        type_col = type_name
                        break
                
                # Expand nested fields if Type column exists
                if type_col:
                    expanded_columns = []
                    for i, col in enumerate(columns):
                        expanded_columns.append(col)
                        # Check if this is a row type with nested fields
                        col_type = str(df.iloc[i][type_col]).lower()
                        if 'row(' in col_type:
                            # Extract nested field names from type definition
                            nested_fields = self._extract_nested_fields(col, col_type)
                            expanded_columns.extend(nested_fields)
                    return expanded_columns
                else:
                    return columns
            else:
                return []
        except Exception as e:
            print(f"Error describing table {table_name}: {e}")
            return []
    
    def _extract_nested_fields(self, parent_field: str, type_def: str, max_depth: int = 3) -> list:
        """
        Extract nested field names from a type definition.
        
        Args:
            parent_field: Name of the parent field
            type_def: Type definition string (e.g., 'row(field1 varchar, field2 int)')
            max_depth: Maximum nesting depth to explore
        
        Returns:
            List of nested field paths (e.g., ['parent.field1', 'parent.field2'])
        """
        nested_fields = []
        
        # Simple parsing of row/struct types
        # Look for pattern: row(field_name type, field_name type, ...)
        type_def_lower = type_def.lower()
        if 'row(' in type_def_lower:
            # Extract content between parentheses (case-insensitive search)
            start_pos = type_def_lower.find('row(')
            start = start_pos + 4
            depth = 1
            end = start
            
            for i in range(start, len(type_def)):
                if type_def[i] == '(':
                    depth += 1
                elif type_def[i] == ')':
                    depth -= 1
                    if depth == 0:
                        end = i
                        break
            
            if end > start:
                content = type_def[start:end]
                # Split by comma, but be careful of nested structures
                fields = self._split_fields(content)
                
                for field in fields:
                    # Extract field name (first word before space)
                    field = field.strip()
                    if ' ' in field:
                        field_name = field.split()[0]
                        field_type = field[len(field_name):].strip()
                        
                        # Add this nested field
                        nested_path = f"{parent_field}.{field_name}"
                        nested_fields.append(nested_path)
                        
                        # Recursively handle deeper nesting (up to max_depth)
                        if max_depth > 1 and ('row(' in field_type.lower() or 'struct' in field_type.lower()):
                            deeper_fields = self._extract_nested_fields(nested_path, field_type, max_depth - 1)
                            nested_fields.extend(deeper_fields)
        
        return nested_fields
    
    def _split_fields(self, content: str) -> list:
        """
        Split field definitions by comma, handling nested structures.
        
        Args:
            content: String containing field definitions
        
        Returns:
            List of field definition strings
        """
        fields = []
        current_field = ""
        depth = 0
        
        for char in content:
            if char == '(' or char == '<':
                depth += 1
                current_field += char
            elif char == ')' or char == '>':
                depth -= 1
                current_field += char
            elif char == ',' and depth == 0:
                if current_field.strip():
                    fields.append(current_field.strip())
                current_field = ""
            else:
                current_field += char
        
        # Add the last field
        if current_field.strip():
            fields.append(current_field.strip())
        
        return fields
    
    def _build_column_mappings(self, tab_index: int):
        """
        Build dropdown widgets for mapping strategy inputs to table columns.
        
        Args:
            tab_index: Index of the tab
        """
        tab_data = self.strategy_tab_contents[tab_index]
        strategy = tab_data['strategy']
        available_columns = tab_data['available_columns']
        
        if not available_columns:
            tab_data['column_mapping_container'].children = []
            return
        
        # Create a dropdown for each required input
        dropdowns = []
        tab_data['column_dropdowns'] = {}
        
        for required_input in strategy.required_inputs:
            dropdown = widgets.Dropdown(
                options=available_columns,
                description=f'{required_input}:',
                style={'description_width': 'initial'}
            )
            dropdowns.append(dropdown)
            tab_data['column_dropdowns'][required_input] = dropdown
        
        # Update container
        tab_data['column_mapping_container'].children = dropdowns
    
    def _run_parallel_analysis(self, strategy: HuntStrategy, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Run strategy analysis with multiprocessing support.
        
        This method attempts to parallelize the analysis by checking if the strategy
        has a parallel_analyze method. If not, it falls back to the standard analyze method.
        
        Args:
            strategy: The hunt strategy to execute
            df: Input DataFrame with raw data
            col_map: Dictionary mapping required_inputs to actual column names
        
        Returns:
            DataFrame with analysis results
        """
        # Check if strategy supports parallel processing
        # Only use parallel processing if the method has been overridden (not just inherited)
        strategy_class = strategy.__class__
        base_class = HuntStrategy
        has_custom_parallel = (hasattr(strategy_class, 'parallel_analyze') and 
                               strategy_class.parallel_analyze != base_class.parallel_analyze)
        
        if has_custom_parallel:
            try:
                # Determine optimal number of cores (leave one free, minimum 2 for parallelism)
                total_cores = cpu_count()
                num_cores = max(2, total_cores - 1) if total_cores > 2 else 1
                
                if num_cores > 1:
                    print(f"   Using {num_cores} CPU cores for parallel processing...")
                    return strategy.parallel_analyze(df, col_map, num_cores)
                else:
                    # Not enough cores for parallelism, use standard analysis
                    return strategy.analyze(df, col_map)
            except Exception as e:
                print(f"   ⚠️  Parallel processing failed, falling back to single-threaded: {e}")
                return strategy.analyze(df, col_map)
        else:
            # Standard single-threaded analysis
            return strategy.analyze(df, col_map)
    
    def _run_analysis(self, button, tab_index: int):
        """
        Execute the selected hunt strategy on the selected table.
        
        Args:
            button: Button widget that triggered this callback
            tab_index: Index of the tab
        """
        tab_data = self.strategy_tab_contents[tab_index]
        strategy = tab_data['strategy']
        current_table = tab_data['table_dropdown'].value
        column_dropdowns = tab_data['column_dropdowns']
        
        # Clear previous output
        with tab_data['output_widget']:
            clear_output(wait=True)
        
        # Validate selections
        if not current_table or current_table in ['No tables available', 'Error loading tables', 'No matching tables']:
            with tab_data['output_widget']:
                print("⚠️ Please select a valid table.")
            return
        
        if not column_dropdowns:
            with tab_data['output_widget']:
                print("⚠️ Please load table schema first (click 'Load Table Schema' button).")
            return
        
        # Build column mapping
        col_map = {}
        for required_input, dropdown in column_dropdowns.items():
            col_map[required_input] = dropdown.value
        
        # Build SELECT query with sanitized identifiers, date filtering, and LIMIT
        try:
            # Sanitize all column names and table name
            sanitized_columns = [self._sanitize_identifier(col) for col in col_map.values()]
            sanitized_table = self._sanitize_identifier(current_table)
            
            # Validate and sanitize limit value (IntText widget provides basic validation)
            limit = max(1, min(1000000, int(tab_data['limit_input'].value)))
            
            # Build the query
            query = f"SELECT {', '.join(sanitized_columns)} FROM {sanitized_table}"
            
            # Add date filtering if enabled
            where_clauses = []
            if tab_data['enable_date_filter'].value:
                # Find timestamp column for date filtering
                timestamp_col = col_map.get('timestamp')
                if timestamp_col:
                    sanitized_ts_col = self._sanitize_identifier(timestamp_col)
                    
                    if tab_data['start_date'].value:
                        # Validate date value - DatePicker should provide datetime.date object
                        start_date = tab_data['start_date'].value
                        if not isinstance(start_date, (date, datetime.datetime)):
                            with tab_data['output_widget']:
                                print("⚠️ Invalid start date format")
                            return
                        start_date_str = start_date.isoformat() if hasattr(start_date, 'isoformat') else str(start_date)
                        # Sanitize date string - ensure it matches YYYY-MM-DD format
                        if not re.match(r'^\d{4}-\d{2}-\d{2}$', start_date_str):
                            with tab_data['output_widget']:
                                print("⚠️ Invalid start date format")
                            return
                        where_clauses.append(f"CAST({sanitized_ts_col} AS DATE) >= DATE '{start_date_str}'")
                    
                    if tab_data['end_date'].value:
                        # Validate date value - DatePicker should provide datetime.date object
                        end_date = tab_data['end_date'].value
                        if not isinstance(end_date, (date, datetime.datetime)):
                            with tab_data['output_widget']:
                                print("⚠️ Invalid end date format")
                            return
                        end_date_str = end_date.isoformat() if hasattr(end_date, 'isoformat') else str(end_date)
                        # Sanitize date string - ensure it matches YYYY-MM-DD format
                        if not re.match(r'^\d{4}-\d{2}-\d{2}$', end_date_str):
                            with tab_data['output_widget']:
                                print("⚠️ Invalid end date format")
                            return
                        where_clauses.append(f"CAST({sanitized_ts_col} AS DATE) <= DATE '{end_date_str}'")
                else:
                    # Warn user that date filtering requires timestamp column
                    with tab_data['output_widget']:
                        print("⚠️ Date filtering requires a 'timestamp' column to be mapped. Please load the table schema and ensure a timestamp field is available.")
                    return
            
            if where_clauses:
                query += " WHERE " + " AND ".join(where_clauses)
            
            query += f" LIMIT {limit}"
            
        except ValueError as e:
            with tab_data['output_widget']:
                print(f"❌ Invalid SQL identifier: {e}")
            return
        
        with tab_data['output_widget']:
            print(f"🔍 Running {strategy.name}...")
            print(f"📊 Query: {query}")
            print()
            
            # Create progress indicator
            progress_bar = widgets.IntProgress(
                value=0,
                min=0,
                max=100,
                description='Progress:',
                bar_style='info',
                style={'bar_color': '#667eea'},
                orientation='horizontal'
            )
            progress_label = widgets.HTML(value="<b>Querying database...</b>")
            progress_box = widgets.VBox([progress_label, progress_bar])
            display(progress_box)
            
            try:
                # Execute query
                progress_bar.value = 20
                df = isf.run_query(query)
                
                if df is None or df.empty:
                    progress_box.close()
                    print("⚠️ Query returned no data.")
                    return
                
                progress_bar.value = 40
                progress_label.value = f"<b>Retrieved {len(df)} rows, analyzing...</b>"
                print(f"✅ Retrieved {len(df)} rows from {current_table}")
                print()
                
                # Run strategy analysis with multiprocessing support and time tracking
                print(f"🔬 Analyzing data with {strategy.name}...")
                progress_bar.value = 60
                
                # Track execution time
                analysis_start_time = time.time()
                result_df = self._run_parallel_analysis(strategy, df, col_map)
                analysis_duration = time.time() - analysis_start_time
                
                progress_bar.value = 100
                progress_label.value = "<b>Analysis complete!</b>"
                progress_bar.bar_style = 'success'
                
                # Hide progress bar after a moment
                time.sleep(0.5)
                progress_box.close()
                
                if result_df is None or result_df.empty:
                    print("⚠️ Analysis returned no results.")
                    return
                
                print(f"✅ Analysis complete! Found {len(result_df)} results.")
                rows_per_sec = len(df) / analysis_duration if analysis_duration > 0 else 0
                print(f"⏱️  Analysis time: {analysis_duration:.2f} seconds ({rows_per_sec:.0f} rows/sec)")
                print()
                
                # Store results for correlation analysis
                self.strategy_results[strategy.name] = {
                    'dataframe': result_df.copy(),
                    'strategy': strategy,
                    'timestamp': datetime.datetime.now()
                }
                
                # Store performance metrics
                self.strategy_performance[strategy.name] = {
                    'execution_time': analysis_duration,
                    'rows_analyzed': len(df),
                    'rows_per_second': len(df) / analysis_duration if analysis_duration > 0 else 0,
                    'detections': len(result_df),
                    'detection_rate': len(result_df) / len(df) * 100 if len(df) > 0 else 0,
                    'timestamp': datetime.datetime.now()
                }
                
                # Display summary statistics dashboard
                self._display_summary_stats(result_df, strategy)
                
                # Display column explanations for junior analysts
                explanations = strategy.get_column_explanations()
                if explanations:
                    # Create collapsible explanation section
                    self._display_collapsible_explanations(explanations, result_df)
                
                # Generate and display visualization if available
                viz = strategy.visualize(result_df, col_map)
                if viz is not None:
                    print("📊 Interactive Visualization:")
                    print("-" * 80)
                    display(viz)
                    print()
                
                print("📈 Results (sortable and exportable):")
                print("-" * 80)
                
                # Display results in sortable table with export option
                self._display_sortable_results(result_df, strategy.name)
                
                # Show correlation button if multiple strategies have results
                if len(self.strategy_results) > 1:
                    print()
                    print("🔗 Multiple strategies have results. Generate a correlation analysis:")
                    corr_button = widgets.Button(
                        description='🎯 View Threat Correlation',
                        button_style='warning',
                        icon='search',
                        layout=widgets.Layout(width='250px')
                    )
                    corr_output = widgets.Output()
                    
                    def on_correlation_click(b):
                        with corr_output:
                            clear_output(wait=True)
                            self._show_correlation_analysis()
                    
                    corr_button.on_click(on_correlation_click)
                    display(widgets.VBox([corr_button, corr_output]))
                
            except Exception as e:
                print(f"❌ Error during analysis: {e}")
                import traceback
                traceback.print_exc()
    
    def _show_correlation_analysis(self):
        """
        Display correlation analysis showing IPs that appear in multiple strategies.
        """
        if len(self.strategy_results) < 2:
            print("⚠️ Need results from at least 2 strategies for correlation analysis.")
            return
        
        print("🎯 Cross-Strategy Threat Correlation Analysis")
        print("=" * 80)
        print()
        
        # Identify common IP columns across strategies
        ip_columns = ['source_ip', 'dest_ip']
        
        # Build correlation data
        ip_to_strategies = {}  # Maps IP -> list of (strategy_name, score)
        
        for strategy_name, result_data in self.strategy_results.items():
            df = result_data['dataframe']
            
            # Find score column
            score_cols = [col for col in df.columns if col.endswith('_score')]
            score_col = score_cols[0] if score_cols else None
            
            # Check each IP column
            for ip_col in ip_columns:
                if ip_col in df.columns:
                    for _, row in df.iterrows():
                        ip = row[ip_col]
                        score = row[score_col] if score_col else 0
                        
                        if ip not in ip_to_strategies:
                            ip_to_strategies[ip] = []
                        
                        ip_to_strategies[ip].append({
                            'strategy': strategy_name,
                            'score': score,
                            'role': ip_col
                        })
        
        # Find IPs appearing in multiple strategies
        multi_strategy_ips = {ip: data for ip, data in ip_to_strategies.items() 
                              if len(set(d['strategy'] for d in data)) > 1}
        
        if not multi_strategy_ips:
            print("✅ No IPs found across multiple detection strategies.")
            print("This is generally good - indicates no systematic attackers.")
            return
        
        print(f"⚠️ Found {len(multi_strategy_ips)} IPs appearing in multiple strategies:")
        print()
        
        # Sort by number of strategies detected in
        sorted_ips = sorted(multi_strategy_ips.items(), 
                           key=lambda x: len(set(d['strategy'] for d in x[1])), 
                           reverse=True)
        
        # Build correlation report
        correlation_data = []
        for ip, detections in sorted_ips[:MAX_DISPLAY_ITEMS]:
            strategies_detected = set(d['strategy'] for d in detections)
            avg_score = sum(d['score'] for d in detections) / len(detections)
            max_score = max(d['score'] for d in detections)
            
            correlation_data.append({
                'IP Address': ip,
                'Strategies': len(strategies_detected),
                'Detection Names': ', '.join(sorted(strategies_detected)[:3]) + ('...' if len(strategies_detected) > 3 else ''),
                'Avg Score': f"{avg_score:.1f}",
                'Max Score': f"{max_score:.1f}",
                'Threat Level': 'CRITICAL' if max_score >= HIGH_SEVERITY_THRESHOLD else 'HIGH' if max_score >= MEDIUM_SEVERITY_THRESHOLD else 'MEDIUM'
            })
        
        corr_df = pd.DataFrame(correlation_data)
        
        # Display summary
        critical_count = len([d for d in correlation_data if d['Threat Level'] == 'CRITICAL'])
        high_count = len([d for d in correlation_data if d['Threat Level'] == 'HIGH'])
        
        summary_html = f"""
        <div style="background: {GRADIENT_RED_DANGER}; color: white; padding: 20px; border-radius: 10px; margin: 10px 0;">
            <h3 style="margin-top: 0;">🚨 Correlated Threats Summary</h3>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-top: 15px;">
                <div style="{CSS_STAT_BOX}">
                    <div style="{CSS_HEADING_LARGE}">{len(multi_strategy_ips)}</div>
                    <div style="{CSS_TEXT_SUBTLE}">Correlated IPs</div>
                </div>
                <div style="{CSS_STAT_BOX}">
                    <div style="{CSS_HEADING_LARGE}; color: #ff6b6b;">{critical_count}</div>
                    <div style="{CSS_TEXT_SUBTLE}">Critical Threats</div>
                </div>
                <div style="{CSS_STAT_BOX}">
                    <div style="{CSS_HEADING_LARGE}; color: #ffd93d;">{high_count}</div>
                    <div style="{CSS_TEXT_SUBTLE}">High Priority</div>
                </div>
                <div style="{CSS_STAT_BOX}">
                    <div style="{CSS_HEADING_LARGE}">{len(self.strategy_results)}</div>
                    <div style="{CSS_TEXT_SUBTLE}">Strategies Analyzed</div>
                </div>
            </div>
        </div>
        """
        display(HTML(summary_html))
        print()
        
        # Display correlation table with color coding
        print("📊 Top Correlated Threats:")
        print("-" * 80)
        
        # Create styled HTML table
        table_html = '<table border="1" class="dataframe" style="border-collapse: collapse; width: 100%;">\n'
        table_html += '  <thead>\n    <tr style="text-align: right; background-color: #e74c3c; color: white;">\n'
        for col in corr_df.columns:
            table_html += f'      <th style="padding: 8px; border: 1px solid #ddd;">{html_lib.escape(str(col))}</th>\n'
        table_html += '    </tr>\n  </thead>\n  <tbody>\n'
        
        for _, row in corr_df.iterrows():
            threat_level = row['Threat Level']
            if threat_level == 'CRITICAL':
                bg_color = COLOR_HIGH_SEVERITY_BG
                badge_color = COLOR_HIGH_SEVERITY_BADGE
            elif threat_level == 'HIGH':
                bg_color = COLOR_MEDIUM_SEVERITY_BG
                badge_color = COLOR_MEDIUM_SEVERITY_BADGE
            else:
                bg_color = COLOR_LOW_SEVERITY_BG
                badge_color = COLOR_LOW_SEVERITY_BADGE
            
            table_html += f'    <tr style="background-color: {bg_color};">\n'
            for col in corr_df.columns:
                value = row[col]
                if col == 'Threat Level':
                    # Threat level is our own controlled value, safe to insert
                    badge = f'<span style="background: {badge_color}; color: white; padding: 2px 8px; border-radius: 3px; font-size: 0.8em; font-weight: bold;">{html_lib.escape(str(value))}</span>'
                    table_html += f'      <td style="padding: 8px; border: 1px solid #ddd;">{badge}</td>\n'
                else:
                    # Escape all other values
                    table_html += f'      <td style="padding: 8px; border: 1px solid #ddd;">{html_lib.escape(str(value))}</td>\n'
            table_html += '    </tr>\n'
        
        table_html += '  </tbody>\n</table>'
        display(HTML(table_html))
        
        # Try to create visualization if plotly is available
        try:
            import plotly.graph_objects as go
            
            # Create bubble chart: strategies vs max score
            viz_data = []
            for ip, detections in sorted_ips[:MAX_DISPLAY_ITEMS]:
                strategies_detected = set(d['strategy'] for d in detections)
                max_score = max(d['score'] for d in detections)
                viz_data.append({
                    'ip': ip,
                    'strategies': len(strategies_detected),
                    'score': max_score
                })
            
            viz_df = pd.DataFrame(viz_data)
            
            fig = go.Figure()
            fig.add_trace(go.Scatter(
                x=viz_df['strategies'],
                y=viz_df['score'],
                mode='markers',
                marker=dict(
                    size=15,
                    color=viz_df['score'],
                    colorscale='Reds',
                    showscale=True,
                    colorbar=dict(title="Max<br>Score"),
                    line=dict(width=1, color='white')
                ),
                text=[f"IP: {html_lib.escape(str(viz_df.iloc[i]['ip']))}<br>Strategies: {viz_df.iloc[i]['strategies']}<br>Score: {viz_df.iloc[i]['score']:.1f}"
                      for i in range(len(viz_df))],
                hovertemplate='%{text}<extra></extra>'
            ))
            
            fig.update_layout(
                title="Correlation Analysis: Detection Breadth vs Threat Score",
                xaxis_title="Number of Strategies Detecting This IP",
                yaxis_title="Maximum Threat Score",
                hovermode='closest',
                height=500,
                showlegend=False
            )
            
            print()
            print("📊 Interactive Correlation Visualization:")
            print("-" * 80)
            display(fig)
            print()
        except ImportError:
            pass  # Plotly not available, skip visualization
        
        # Export option
        print()
        export_button = widgets.Button(
            description='📥 Export Correlation Report',
            button_style='success',
            icon='download'
        )
        export_output = widgets.Output()
        
        def on_export_corr(b):
            with export_output:
                clear_output(wait=True)
                try:
                    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
                    filename = f"threat_correlation_{timestamp}.csv"
                    corr_df.to_csv(filename, index=False)
                    print(f"✅ Exported correlation report to {filename}")
                except Exception as e:
                    print(f"❌ Export failed: {e}")
        
        export_button.on_click(on_export_corr)
        display(widgets.VBox([export_button, export_output]))
        print()
        print("💡 Tip: IPs appearing in multiple strategies warrant immediate investigation!")
    
    def _show_quick_triage(self):
        """
        Display a quick triage view showing all high-severity threats across all strategies.
        """
        if not self.strategy_results:
            print("⚠️ No strategy results available yet. Run some analyses first!")
            return
        
        print("🚨 Quick Triage - All High-Priority Threats")
        print("=" * 80)
        print()
        
        # Collect all high-severity findings
        high_severity_findings = []
        
        for strategy_name, result_data in self.strategy_results.items():
            df = result_data['dataframe']
            
            # Find score column
            score_cols = [col for col in df.columns if col.endswith('_score')]
            if not score_cols:
                continue
            
            score_col = score_cols[0]
            
            # Filter high-severity
            high_severity_df = df[df[score_col] >= HIGH_SEVERITY_THRESHOLD]
            
            for _, row in high_severity_df.iterrows():
                finding = {
                    'Strategy': strategy_name.split('(')[0].strip(),  # Short name
                    'Score': row[score_col],
                }
                
                # Add key identifying information
                if 'source_ip' in row:
                    finding['Source IP'] = row['source_ip']
                if 'dest_ip' in row:
                    finding['Dest IP'] = row['dest_ip']
                if 'target_string' in row:
                    finding['Target'] = str(row['target_string'])[:STRING_TRUNCATE_LENGTH]
                
                high_severity_findings.append(finding)
        
        if not high_severity_findings:
            print("✅ No high-severity threats found across all strategies!")
            print("System appears to be in good health.")
            return
        
        # Create summary
        summary_html = f"""
        <div style="background: {GRADIENT_RED_DANGER}; color: white; padding: 20px; border-radius: 10px; margin: 10px 0;">
            <h3 style="margin-top: 0;">🚨 Quick Triage Summary</h3>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-top: 15px;">
                <div style="{CSS_STAT_BOX}">
                    <div style="{CSS_HEADING_LARGE}">{len(high_severity_findings)}</div>
                    <div style="{CSS_TEXT_SUBTLE}">Critical Threats</div>
                </div>
                <div style="{CSS_STAT_BOX}">
                    <div style="{CSS_HEADING_LARGE}">{len(self.strategy_results)}</div>
                    <div style="{CSS_TEXT_SUBTLE}">Strategies Analyzed</div>
                </div>
                <div style="{CSS_STAT_BOX}">
                    <div style="{CSS_HEADING_LARGE}">{len(set(f.get('Source IP', '') for f in high_severity_findings if f.get('Source IP')))}</div>
                    <div style="{CSS_TEXT_SUBTLE}">Unique Source IPs</div>
                </div>
            </div>
        </div>
        """
        display(HTML(summary_html))
        print()
        
        # Display findings table
        triage_df = pd.DataFrame(high_severity_findings)
        
        # Sort by score descending
        triage_df = triage_df.sort_values('Score', ascending=False)
        
        print(f"📊 All High-Severity Findings (Score ≥ {HIGH_SEVERITY_THRESHOLD}):")
        print("-" * 80)
        # Use escape=True (default) to prevent XSS
        display(HTML(triage_df.to_html(index=False)))
        
        # Export option
        print()
        export_button = widgets.Button(
            description='📥 Export Triage Report',
            button_style='success',
            icon='download'
        )
        export_output = widgets.Output()
        
        def on_export_triage(b):
            with export_output:
                clear_output(wait=True)
                try:
                    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
                    filename = f"quick_triage_{timestamp}.csv"
                    triage_df.to_csv(filename, index=False)
                    print(f"✅ Exported triage report to {filename}")
                except Exception as e:
                    print(f"❌ Export failed: {e}")
        
        export_button.on_click(on_export_triage)
        display(widgets.VBox([export_button, export_output]))
        print()
        print(f"💡 Tip: Prioritize investigation of threats with scores ≥ {CRITICAL_SEVERITY_THRESHOLD}!")
    
    def _generate_investigation_report(self):
        """
        Generate a comprehensive HTML investigation report with all findings.
        """
        if not self.strategy_results:
            print("⚠️ No results available. Run some analyses first!")
            return
        
        print("📄 Generating Investigation Report...")
        
        timestamp = datetime.datetime.now()
        report_filename = f"investigation_report_{timestamp.strftime('%Y%m%d_%H%M%S')}.html"
        
        # Start building HTML report
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>221B Threat Hunting Investigation Report</title>
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    margin: 0;
                    padding: 20px;
                    background: #f5f5f5;
                }}
                .container {{
                    max-width: 1200px;
                    margin: 0 auto;
                    background: white;
                    padding: 30px;
                    border-radius: 10px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                }}
                h1 {{
                    color: #2c3e50;
                    border-bottom: 3px solid #3498db;
                    padding-bottom: 10px;
                }}
                h2 {{
                    color: #34495e;
                    margin-top: 30px;
                    border-left: 4px solid #3498db;
                    padding-left: 15px;
                }}
                .summary-card {{
                    background: {GRADIENT_PURPLE_VIOLET};
                    color: white;
                    padding: 20px;
                    border-radius: 10px;
                    margin: 20px 0;
                }}
                .stats-grid {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 15px;
                    margin-top: 15px;
                }}
                .stat-box {{
                    background: rgba(255,255,255,0.2);
                    padding: 15px;
                    border-radius: 8px;
                    text-align: center;
                }}
                .stat-value {{
                    font-size: 2em;
                    font-weight: bold;
                }}
                .stat-label {{
                    font-size: 0.9em;
                    opacity: 0.9;
                }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin: 20px 0;
                }}
                th {{
                    background: #34495e;
                    color: white;
                    padding: 12px;
                    text-align: left;
                }}
                td {{
                    padding: 10px;
                    border: 1px solid #ddd;
                }}
                tr:nth-child(even) {{
                    background: #f9f9f9;
                }}
                .severity-high {{
                    background: {COLOR_HIGH_SEVERITY_BG} !important;
                }}
                .severity-medium {{
                    background: {COLOR_MEDIUM_SEVERITY_BG} !important;
                }}
                .severity-low {{
                    background: {COLOR_LOW_SEVERITY_BG} !important;
                }}
                .badge {{
                    padding: 4px 10px;
                    border-radius: 4px;
                    font-size: 0.85em;
                    font-weight: bold;
                    color: white;
                }}
                .badge-high {{ background: {COLOR_HIGH_SEVERITY_BADGE}; }}
                .badge-medium {{ background: {COLOR_MEDIUM_SEVERITY_BADGE}; }}
                .badge-low {{ background: {COLOR_LOW_SEVERITY_BADGE}; }}
                .footer {{
                    margin-top: 40px;
                    padding-top: 20px;
                    border-top: 2px solid #eee;
                    text-align: center;
                    color: #7f8c8d;
                    font-size: 0.9em;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🔍 221B Threat Hunting Investigation Report</h1>
                <p><strong>Generated:</strong> {timestamp.strftime('%Y-%m-%d %H:%M:%S')}</p>
                
                <div class="summary-card">
                    <h3 style="margin-top: 0;">Executive Summary</h3>
                    <div class="stats-grid">
        """
        
        # Calculate overall statistics
        total_findings = sum(len(r['dataframe']) for r in self.strategy_results.values())
        high_severity = 0
        medium_severity = 0
        
        for result_data in self.strategy_results.values():
            df = result_data['dataframe']
            score_cols = [col for col in df.columns if col.endswith('_score')]
            if score_cols:
                score_col = score_cols[0]
                high_severity += len(df[df[score_col] >= HIGH_SEVERITY_THRESHOLD])
                medium_severity += len(df[(df[score_col] >= MEDIUM_SEVERITY_THRESHOLD) & (df[score_col] < HIGH_SEVERITY_THRESHOLD)])
        
        html += f"""
                        <div class="stat-box">
                            <div class="stat-value">{len(self.strategy_results)}</div>
                            <div class="stat-label">Strategies Executed</div>
                        </div>
                        <div class="stat-box">
                            <div class="stat-value">{total_findings}</div>
                            <div class="stat-label">Total Findings</div>
                        </div>
                        <div class="stat-box">
                            <div class="stat-value">{high_severity}</div>
                            <div class="stat-label">High Severity</div>
                        </div>
                        <div class="stat-box">
                            <div class="stat-value">{medium_severity}</div>
                            <div class="stat-label">Medium Severity</div>
                        </div>
                    </div>
                </div>
        """
        
        # Add findings by strategy
        for strategy_name, result_data in self.strategy_results.items():
            df = result_data['dataframe']
            strategy = result_data['strategy']
            
            # Escape HTML in user-controlled content
            safe_strategy_name = html_lib.escape(strategy_name)
            strategy_doc = strategy.__class__.__doc__
            safe_doc = html_lib.escape(strategy_doc.strip()) if strategy_doc else 'No description available'
            
            html += f"""
                <h2>{safe_strategy_name}</h2>
                <p><em>{safe_doc}</em></p>
                <p><strong>Findings:</strong> {len(df)} total</p>
            """
            
            # Find score column
            score_cols = [col for col in df.columns if col.endswith('_score')]
            
            if not df.empty:
                # Show top 10 findings
                display_df = df.head(10).copy()
                
                html += '<table><thead><tr>'
                for col in display_df.columns:
                    html += f'<th>{html_lib.escape(str(col))}</th>'
                html += '</tr></thead><tbody>'
                
                for _, row in display_df.iterrows():
                    # Determine severity class
                    severity_class = ''
                    if score_cols:
                        score = row[score_cols[0]]
                        if score >= HIGH_SEVERITY_THRESHOLD:
                            severity_class = 'severity-high'
                        elif score >= MEDIUM_SEVERITY_THRESHOLD:
                            severity_class = 'severity-medium'
                        else:
                            severity_class = 'severity-low'
                    
                    html += f'<tr class="{severity_class}">'
                    for col in display_df.columns:
                        value = row[col]
                        # Add badge for score columns
                        if col.endswith('_score'):
                            if value >= HIGH_SEVERITY_THRESHOLD:
                                badge_class = 'badge-high'
                                badge_text = 'HIGH'
                            elif value >= MEDIUM_SEVERITY_THRESHOLD:
                                badge_class = 'badge-medium'
                                badge_text = 'MED'
                            else:
                                badge_class = 'badge-low'
                                badge_text = 'LOW'
                            html += f'<td>{value:.1f} <span class="badge {badge_class}">{badge_text}</span></td>'
                        else:
                            # Escape all values to prevent XSS
                            html += f'<td>{html_lib.escape(str(value))}</td>'
                    html += '</tr>'
                
                html += '</tbody></table>'
                
                if len(df) > 10:
                    html += f'<p><em>... and {len(df) - 10} more findings</em></p>'
            else:
                html += '<p><em>No findings for this strategy.</em></p>'
        
        # Add footer
        html += """
                <div class="footer">
                    <p>Generated by 221B Interactive Threat Hunting Dashboard</p>
                    <p>This report contains sensitive security information - handle appropriately</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Write report to file
        try:
            with open(report_filename, 'w', encoding='utf-8') as f:
                f.write(html)
            print(f"✅ Investigation report generated: {report_filename}")
            print(f"📊 Report contains {total_findings} findings from {len(self.strategy_results)} strategies")
            print(f"🚨 {high_severity} high-severity threats identified")
            print()
            print(f"💡 Open {report_filename} in your browser to view the full report")
        except Exception as e:
            print(f"❌ Failed to generate report: {e}")
    
    def _export_all_results(self, export_format='csv'):
        """
        Export all strategy results to individual files.
        
        Args:
            export_format: Format to export ('csv' or 'json')
        """
        if not self.strategy_results:
            print("⚠️ No analysis results available to export.")
            print("💡 Run some strategies first, then use this button to export all results at once.")
            return
        
        print(f"💾 Exporting all strategy results as {export_format.upper()}...")
        print("=" * 80)
        print()
        
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        export_count = 0
        total_rows = 0
        
        for strategy_name, result_data in self.strategy_results.items():
            df = result_data['dataframe']
            
            if df.empty:
                print(f"⚠️ {strategy_name}: No data to export")
                continue
            
            # Use consolidated export helper
            success, filename, error = self._export_dataframe(df, strategy_name, export_format)
            
            if success:
                export_count += 1
                total_rows += len(df)
                
                # Find score column for stats
                score_cols = [col for col in df.columns if col.endswith('_score')]
                if score_cols:
                    score_col = score_cols[0]
                    high_count = len(df[df[score_col] >= HIGH_SEVERITY_THRESHOLD])
                    print(f"✅ {strategy_name}: {len(df)} rows exported to {filename} ({high_count} high-severity)")
                else:
                    print(f"✅ {strategy_name}: {len(df)} rows exported to {filename}")
            else:
                print(f"❌ {strategy_name}: Export failed - {error}")
        
        print()
        print("=" * 80)
        print("📊 Export Summary:")
        print(f"   • Format: {export_format.upper()}")
        print(f"   • Files created: {export_count}")
        print(f"   • Total rows: {total_rows}")
        print(f"   • Timestamp: {timestamp}")
        print()
        
        if export_format == 'json':
            print("💡 JSON files are ready for API ingestion, SIEM integration, or custom analysis")
        else:
            print("💡 CSV files are ready for analysis in Excel, Splunk, or other tools")
    
    def display(self):
        """
        Display the complete dashboard UI.
        
        Arranges all widgets in a vertical layout and displays them.
        """
        # Create header
        header = widgets.HTML(
            value="""
            <h2>🔍 221B: The Analyst's Head-Up Display</h2>
            <p>Select a hunt strategy tab below to begin your analysis.</p>
            """
        )
        
        # Create quick action buttons
        triage_button = widgets.Button(
            description='🚨 Quick Triage',
            button_style='danger',
            tooltip='View all high-severity threats across all strategies',
            icon='exclamation-triangle',
            layout=widgets.Layout(width='150px')
        )
        
        correlation_button = widgets.Button(
            description='🔗 Correlations',
            button_style='warning',
            tooltip='Find IPs appearing in multiple strategies',
            icon='link',
            layout=widgets.Layout(width='150px')
        )
        
        report_button = widgets.Button(
            description='📄 Generate Report',
            button_style='info',
            tooltip='Generate comprehensive HTML investigation report',
            icon='file-text',
            layout=widgets.Layout(width='180px')
        )
        
        export_all_button = widgets.Button(
            description='💾 Export All',
            button_style='success',
            tooltip='Export all strategy results to CSV files',
            icon='download',
            layout=widgets.Layout(width='150px')
        )
        
        metrics_button = widgets.Button(
            description='📊 Metrics Dashboard',
            button_style='primary',
            tooltip='View comprehensive threat intelligence dashboard',
            icon='dashboard',
            layout=widgets.Layout(width='180px')
        )
        
        performance_button = widgets.Button(
            description='⚡ Performance',
            button_style='',
            tooltip='View strategy execution performance statistics',
            icon='clock-o',
            layout=widgets.Layout(width='140px')
        )
        
        timeline_button = widgets.Button(
            description='📅 Timeline',
            button_style='',
            tooltip='View temporal threat activity heatmap',
            icon='calendar',
            layout=widgets.Layout(width='120px')
        )
        
        recommend_button = widgets.Button(
            description='🎯 Recommendations',
            button_style='',
            tooltip='Get smart recommendations for next steps',
            icon='lightbulb-o',
            layout=widgets.Layout(width='170px')
        )
        
        help_button = widgets.Button(
            description='❓ Tips',
            button_style='',
            tooltip='Show usage tips and best practices',
            icon='question-circle',
            layout=widgets.Layout(width='100px')
        )
        
        heatmap_button = widgets.Button(
            description='🗺️ IP Heatmap',
            button_style='',
            tooltip='View IP address threat heatmap',
            icon='map',
            layout=widgets.Layout(width='140px')
        )
        
        insights_button = widgets.Button(
            description='🎓 Strategy Insights',
            button_style='',
            tooltip='Compare strategy effectiveness and coverage',
            icon='line-chart',
            layout=widgets.Layout(width='170px')
        )
        
        overview_button = widgets.Button(
            description='📊 Threat Overview',
            button_style='info',
            tooltip='Comprehensive dashboard showing all strategies at a glance',
            icon='dashboard',
            layout=widgets.Layout(width='170px')
        )
        
        velocity_button = widgets.Button(
            description='⚡ Threat Velocity',
            button_style='warning',
            tooltip='View real-time threat detection velocity and trends',
            icon='tachometer',
            layout=widgets.Layout(width='160px')
        )
        
        action_output = widgets.Output()
        
        def show_tips():
            """Display usage tips and best practices."""
            # Dynamic strategy count
            strategy_count = len(self.strategies)
            
            tips_html = f"""
            <div style="background: {GRADIENT_PURPLE_VIOLET}; color: white; padding: 20px; border-radius: 10px; margin: 10px 0;">
                <h3 style="margin-top: 0;">💡 Quick Tips & Best Practices</h3>
                
                <h4>🚀 Quick Start Workflow:</h4>
                <ol style="line-height: 1.8;">
                    <li><strong>Select a Strategy Tab</strong> - Choose from {strategy_count} comprehensive threat hunting strategies</li>
                    <li><strong>Read the Recommendation</strong> - Each strategy shows when to use it and what data works best</li>
                    <li><strong>Load Data</strong> - Pick a table and map required columns</li>
                    <li><strong>Run Analysis</strong> - Click the green "Run Analysis" button</li>
                    <li><strong>Review Results</strong> - Use filters to focus on high-severity findings</li>
                </ol>
                
                <h4>🎯 Power User Features:</h4>
                <ul style="line-height: 1.8;">
                    <li><strong>Threat Overview Dashboard:</strong> 🔥 Click 📊 Threat Overview to see ALL strategies at a glance with comprehensive visualizations</li>
                    <li><strong>Threat Velocity Gauge:</strong> 🆕 Click ⚡ Threat Velocity to monitor real-time threat detection rates and trends</li>
                    <li><strong>Metrics Dashboard:</strong> Click 📊 to view real-time threat intelligence with aggregated statistics and strategy comparisons</li>
                    <li><strong>Performance Stats:</strong> Click ⚡ to see execution times, throughput rates, and detection efficiency for each strategy</li>
                    <li><strong>Timeline Analysis:</strong> Click 📅 to visualize when threats occurred with interactive heatmaps and temporal patterns</li>
                    <li><strong>IP Threat Heatmap:</strong> Click 🗺️ to see which IPs generate the most threats across strategies with bubble chart visualization</li>
                    <li><strong>Strategy Insights:</strong> Click 🎓 to compare strategy effectiveness with stacked severity distributions and detection rates</li>
                    <li><strong>Smart Recommendations:</strong> Click 🎯 to get AI-powered suggestions on which strategies to run next based on findings</li>
                    <li><strong>Text Search:</strong> Use the 🔍 search box to filter results across all columns - find IPs, domains, or any text instantly</li>
                    <li><strong>Quick Triage:</strong> After running multiple analyses, click the 🚨 button to see all critical threats at once</li>
                    <li><strong>Correlation Analysis:</strong> Click 🔗 to find IPs appearing in multiple strategies - these are your highest-priority targets</li>
                    <li><strong>HTML Reports:</strong> Generate professional reports with the 📄 button for management briefings</li>
                    <li><strong>Export Options:</strong> 🆕 Export as CSV or JSON - JSON format is ideal for SIEM integration and programmatic analysis</li>
                    <li><strong>Multi-Filter:</strong> Combine text search with severity filters and sorting for precise threat identification</li>
                </ul>
                
                <h4>🔍 Investigation Strategy:</h4>
                <ul style="line-height: 1.8;">
                    <li><strong>Start Broad:</strong> Run multiple strategies on your data to get different perspectives</li>
                    <li><strong>Correlate:</strong> Use correlation analysis to identify systematic attackers</li>
                    <li><strong>Triage:</strong> Focus on high-severity (≥75 score) findings first</li>
                    <li><strong>Document:</strong> Export findings and generate reports for your records</li>
                </ul>
                
                <h4>⚡ Performance Tips:</h4>
                <ul style="line-height: 1.8;">
                    <li>Use date filters to limit data range and improve speed</li>
                    <li>Start with smaller row limits (10,000) for initial exploration</li>
                    <li>Cache is automatically used for table listings (refreshes every 7 days)</li>
                    <li>Results are stored in memory for correlation - no need to re-run analyses</li>
                </ul>
                
                <h4>📊 Understanding Scores:</h4>
                <ul style="line-height: 1.8;">
                    <li><strong>75-100 (Critical):</strong> Strong evidence of malicious activity - investigate immediately</li>
                    <li><strong>50-74 (High):</strong> Suspicious behavior worth investigating</li>
                    <li><strong>&lt;50 (Medium/Low):</strong> Anomalies that may be benign but worth noting</li>
                </ul>
            </div>
            """
            with action_output:
                clear_output(wait=True)
                display(HTML(tips_html))
        
        def on_triage_click(b):
            with action_output:
                clear_output(wait=True)
                self._show_quick_triage()
        
        def on_correlation_click(b):
            with action_output:
                clear_output(wait=True)
                self._show_correlation_analysis()
        
        def on_report_click(b):
            with action_output:
                clear_output(wait=True)
                self._generate_investigation_report()
        
        def on_export_all_click(b):
            with action_output:
                clear_output(wait=True)
                self._export_all_results('csv')
        
        def on_metrics_click(b):
            with action_output:
                clear_output(wait=True)
                self._show_threat_metrics_dashboard()
        
        def on_performance_click(b):
            with action_output:
                clear_output(wait=True)
                self._show_performance_statistics()
        
        def on_timeline_click(b):
            with action_output:
                clear_output(wait=True)
                self._show_threat_timeline()
        
        def on_recommend_click(b):
            with action_output:
                clear_output(wait=True)
                self._show_smart_recommendations()
        
        def on_help_click(b):
            show_tips()
        
        def on_heatmap_click(b):
            with action_output:
                clear_output(wait=True)
                self._show_threat_heatmap()
        
        def on_insights_click(b):
            with action_output:
                clear_output(wait=True)
                self._show_strategy_insights()
        
        def on_overview_click(b):
            with action_output:
                clear_output(wait=True)
                self._show_threat_overview_dashboard()
        
        def on_velocity_click(b):
            with action_output:
                clear_output(wait=True)
                self._show_threat_velocity_gauge()
        
        triage_button.on_click(on_triage_click)
        correlation_button.on_click(on_correlation_click)
        report_button.on_click(on_report_click)
        export_all_button.on_click(on_export_all_click)
        metrics_button.on_click(on_metrics_click)
        performance_button.on_click(on_performance_click)
        timeline_button.on_click(on_timeline_click)
        recommend_button.on_click(on_recommend_click)
        help_button.on_click(on_help_click)
        heatmap_button.on_click(on_heatmap_click)
        insights_button.on_click(on_insights_click)
        overview_button.on_click(on_overview_click)
        velocity_button.on_click(on_velocity_click)
        
        # Split buttons into three rows for better layout
        action_row1 = widgets.HBox([
            triage_button,
            correlation_button,
            report_button,
            export_all_button,
            metrics_button
        ], layout=widgets.Layout(justify_content='flex-start', margin='5px 0'))
        
        action_row2 = widgets.HBox([
            performance_button,
            timeline_button,
            heatmap_button,
            insights_button,
            overview_button
        ], layout=widgets.Layout(justify_content='flex-start', margin='5px 0'))
        
        action_row3 = widgets.HBox([
            velocity_button,
            recommend_button,
            help_button
        ], layout=widgets.Layout(justify_content='flex-start', margin='5px 0'))
        
        action_buttons = widgets.VBox([action_row1, action_row2, action_row3])
        
        # Arrange layout with tabs
        dashboard = widgets.VBox([
            header,
            action_buttons,
            action_output,
            widgets.HTML("<hr>"),
            self.tab_widget,
        ])
        
        # Display
        display(dashboard)
