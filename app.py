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
from datetime import timedelta, date
from multiprocessing import Pool, cpu_count
from ionic_scripting_framework import isf
from strategies import HuntStrategy
import html as html_lib  # For HTML escaping


# Visual styling constants for severity indicators
COLOR_HIGH_SEVERITY_BG = '#ffebee'  # Light red background
COLOR_HIGH_SEVERITY_BADGE = '#f44336'  # Red badge
COLOR_MEDIUM_SEVERITY_BG = '#fff3e0'  # Light orange background
COLOR_MEDIUM_SEVERITY_BADGE = '#ff9800'  # Orange badge
COLOR_LOW_SEVERITY_BG = '#e8f5e9'  # Light green background
COLOR_LOW_SEVERITY_BADGE = '#4caf50'  # Green badge

# Analysis and display constants
HIGH_SEVERITY_THRESHOLD = 75  # Score threshold for high-severity threats
MEDIUM_SEVERITY_THRESHOLD = 50  # Score threshold for medium-severity threats
MAX_DISPLAY_ITEMS = 20  # Maximum items to display in correlation/triage views
STRING_TRUNCATE_LENGTH = 50  # Length to truncate long strings for display


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
        
        # Initialize UI
        self._initialize_ui()
    
    def _initialize_ui(self):
        """Set up the initial UI components."""
        # Query available tables once
        self.all_tables = self._get_available_tables()
        
        # Create tabs for strategies with all widgets inside each tab
        self._create_strategy_tabs()
    
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
                age_seconds = (datetime.datetime.now() - cache_time).total_seconds()
                age_days = age_seconds / 86400  # Convert seconds to days
                
                if age_days < self.cache_days:
                    print(f"📦 Using cached table list (age: {age_days:.1f} days)")
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
            
            description = widgets.HTML(
                value=f"""
                <div style="padding: 10px;">
                    <h3>{strategy.name}</h3>
                    <p style="margin: 10px 0;"><i>{strategy_desc}</i></p>
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
        
        # Build summary HTML
        summary_html = f"""
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; margin: 10px 0;">
            <h3 style="margin-top: 0;">📊 Analysis Summary</h3>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-top: 15px;">
                <div style="background: rgba(255,255,255,0.2); padding: 15px; border-radius: 8px;">
                    <div style="font-size: 2em; font-weight: bold;">{total_results}</div>
                    <div style="font-size: 0.9em; opacity: 0.9;">Suspicious Activities</div>
                </div>
        """
        
        # Add severity breakdown if score columns exist
        if score_cols:
            score_col = score_cols[0]  # Use first score column
            high_severity = len(df[df[score_col] >= 75])
            medium_severity = len(df[(df[score_col] >= 50) & (df[score_col] < 75)])
            
            summary_html += f"""
                <div style="background: rgba(255,255,255,0.2); padding: 15px; border-radius: 8px;">
                    <div style="font-size: 2em; font-weight: bold; color: #ff6b6b;">{high_severity}</div>
                    <div style="font-size: 0.9em; opacity: 0.9;">High Severity (≥75)</div>
                </div>
                <div style="background: rgba(255,255,255,0.2); padding: 15px; border-radius: 8px;">
                    <div style="font-size: 2em; font-weight: bold; color: #ffd93d;">{medium_severity}</div>
                    <div style="font-size: 0.9em; opacity: 0.9;">Medium Severity (50-74)</div>
                </div>
                <div style="background: rgba(255,255,255,0.2); padding: 15px; border-radius: 8px;">
                    <div style="font-size: 2em; font-weight: bold;">{df[score_col].mean():.1f}</div>
                    <div style="font-size: 0.9em; opacity: 0.9;">Average Score</div>
                </div>
            """
        
        summary_html += """
            </div>
        </div>
        """
        
        display(HTML(summary_html))
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
        cached_sorted_df = {'df': full_df, 'total_pages': 1}  # Cache for sorted DataFrame
        
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
        
        # Create export button
        export_button = widgets.Button(
            description='📥 Export CSV',
            button_style='success',
            icon='download',
            layout=widgets.Layout(width='150px')
        )
        
        export_output = widgets.Output()
        
        # Create output area for the table
        table_output = widgets.Output()
        
        def get_sorted_df():
            """Get the dataframe with current sorting and filtering applied (cached)."""
            # First apply filtering
            if has_score_column and current_filter['level'] != 'All':
                if current_filter['level'] == 'High (≥75)':
                    filtered_df = full_df[full_df[score_col] >= 75]
                elif current_filter['level'] == 'Medium (50-74)':
                    filtered_df = full_df[(full_df[score_col] >= 50) & (full_df[score_col] < 75)]
                elif current_filter['level'] == 'Low (<50)':
                    filtered_df = full_df[full_df[score_col] < 50]
                else:
                    filtered_df = full_df
            else:
                filtered_df = full_df
            
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
                # Create styled HTML table with color-coded rows
                table_html = '<table border="1" class="dataframe" style="border-collapse: collapse; width: 100%;">\n'
                table_html += '  <thead>\n    <tr style="text-align: right; background-color: #667eea; color: white;">\n'
                for col in page_df.columns:
                    table_html += f'      <th style="padding: 8px; border: 1px solid #ddd;">{col}</th>\n'
                table_html += '    </tr>\n  </thead>\n  <tbody>\n'
                
                for idx, row in page_df.iterrows():
                    score = row[score_col]
                    # Color code based on severity
                    if score >= 75:
                        bg_color = COLOR_HIGH_SEVERITY_BG
                        badge = f'<span style="background: {COLOR_HIGH_SEVERITY_BADGE}; color: white; padding: 2px 8px; border-radius: 3px; font-size: 0.8em; font-weight: bold;">HIGH</span>'
                    elif score >= 50:
                        bg_color = COLOR_MEDIUM_SEVERITY_BG
                        badge = f'<span style="background: {COLOR_MEDIUM_SEVERITY_BADGE}; color: white; padding: 2px 8px; border-radius: 3px; font-size: 0.8em; font-weight: bold;">MED</span>'
                    else:
                        bg_color = COLOR_LOW_SEVERITY_BG
                        badge = f'<span style="background: {COLOR_LOW_SEVERITY_BADGE}; color: white; padding: 2px 8px; border-radius: 3px; font-size: 0.8em; font-weight: bold;">LOW</span>'
                    
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
        
        def on_export_click(b):
            """Handle export button click."""
            with export_output:
                clear_output(wait=True)
                try:
                    # Generate filename with timestamp
                    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
                    # Sanitize strategy name for filename
                    safe_name = re.sub(r'[^\w\s-]', '', strategy_name).strip().replace(' ', '_')
                    filename = f"{safe_name}_{timestamp}.csv"
                    
                    # Save CSV (use current filtered/sorted df)
                    sorted_df = cached_sorted_df['df']
                    sorted_df.to_csv(filename, index=False)
                    
                    print(f"✅ Exported {len(sorted_df)} rows to {filename}")
                except Exception as e:
                    print(f"❌ Export failed: {e}")
        
        # Attach observers and handlers
        sort_column.observe(on_sort_change, names='value')
        sort_order.observe(on_sort_change, names='value')
        if filter_buttons:
            filter_buttons.observe(on_filter_change, names='value')
        prev_button.on_click(on_prev_click)
        next_button.on_click(on_next_click)
        export_button.on_click(on_export_click)
        
        # Initial display
        update_table()
        
        # Create the UI layout
        sort_controls = widgets.HBox([sort_column, sort_order, export_button])
        pagination_controls = widgets.HBox([prev_button, page_info, next_button], 
                                          layout=widgets.Layout(justify_content='center'))
        
        # Build the results UI components
        ui_components = [
            widgets.HTML("<h4>📊 Results</h4>"),
        ]
        
        # Add filter buttons if score column exists
        if filter_buttons:
            ui_components.append(widgets.HTML("<div style='margin: 5px 0;'><b>Quick Filter:</b></div>"))
            ui_components.append(filter_buttons)
        
        ui_components.extend([
            sort_controls,
            export_output,
            pagination_controls,
            table_output,
            pagination_controls  # Show pagination at bottom too for convenience
        ])
        
        sortable_table = widgets.VBox(ui_components)
        
        display(sortable_table)
    
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
                
                # Run strategy analysis with multiprocessing support
                print(f"🔬 Analyzing data with {strategy.name}...")
                progress_bar.value = 60
                result_df = self._run_parallel_analysis(strategy, df, col_map)
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
                print()
                
                # Store results for correlation analysis
                self.strategy_results[strategy.name] = {
                    'dataframe': result_df.copy(),
                    'strategy': strategy,
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
        <div style="background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%); color: white; padding: 20px; border-radius: 10px; margin: 10px 0;">
            <h3 style="margin-top: 0;">🚨 Correlated Threats Summary</h3>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-top: 15px;">
                <div style="background: rgba(255,255,255,0.2); padding: 15px; border-radius: 8px;">
                    <div style="font-size: 2em; font-weight: bold;">{len(multi_strategy_ips)}</div>
                    <div style="font-size: 0.9em; opacity: 0.9;">Correlated IPs</div>
                </div>
                <div style="background: rgba(255,255,255,0.2); padding: 15px; border-radius: 8px;">
                    <div style="font-size: 2em; font-weight: bold; color: #ff6b6b;">{critical_count}</div>
                    <div style="font-size: 0.9em; opacity: 0.9;">Critical Threats</div>
                </div>
                <div style="background: rgba(255,255,255,0.2); padding: 15px; border-radius: 8px;">
                    <div style="font-size: 2em; font-weight: bold; color: #ffd93d;">{high_count}</div>
                    <div style="font-size: 0.9em; opacity: 0.9;">High Priority</div>
                </div>
                <div style="background: rgba(255,255,255,0.2); padding: 15px; border-radius: 8px;">
                    <div style="font-size: 2em; font-weight: bold;">{len(self.strategy_results)}</div>
                    <div style="font-size: 0.9em; opacity: 0.9;">Strategies Analyzed</div>
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
        <div style="background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%); color: white; padding: 20px; border-radius: 10px; margin: 10px 0;">
            <h3 style="margin-top: 0;">🚨 Quick Triage Summary</h3>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-top: 15px;">
                <div style="background: rgba(255,255,255,0.2); padding: 15px; border-radius: 8px;">
                    <div style="font-size: 2em; font-weight: bold;">{len(high_severity_findings)}</div>
                    <div style="font-size: 0.9em; opacity: 0.9;">Critical Threats</div>
                </div>
                <div style="background: rgba(255,255,255,0.2); padding: 15px; border-radius: 8px;">
                    <div style="font-size: 2em; font-weight: bold;">{len(self.strategy_results)}</div>
                    <div style="font-size: 0.9em; opacity: 0.9;">Strategies Analyzed</div>
                </div>
                <div style="background: rgba(255,255,255,0.2); padding: 15px; border-radius: 8px;">
                    <div style="font-size: 2em; font-weight: bold;">{len(set(f.get('Source IP', '') for f in high_severity_findings if f.get('Source IP')))}</div>
                    <div style="font-size: 0.9em; opacity: 0.9;">Unique Source IPs</div>
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
        print("💡 Tip: Prioritize investigation of threats with scores ≥ 90!")
    
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
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
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
        
        help_button = widgets.Button(
            description='❓ Tips',
            button_style='',
            tooltip='Show usage tips and best practices',
            icon='question-circle',
            layout=widgets.Layout(width='100px')
        )
        
        action_output = widgets.Output()
        
        def show_tips():
            """Display usage tips and best practices."""
            tips_html = """
            <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; margin: 10px 0;">
                <h3 style="margin-top: 0;">💡 Quick Tips & Best Practices</h3>
                
                <h4>🚀 Quick Start Workflow:</h4>
                <ol style="line-height: 1.8;">
                    <li><strong>Select a Strategy Tab</strong> - Choose from 9 threat hunting strategies</li>
                    <li><strong>Load Data</strong> - Pick a table and map required columns</li>
                    <li><strong>Run Analysis</strong> - Click the green "Run Analysis" button</li>
                    <li><strong>Review Results</strong> - Use filters to focus on high-severity findings</li>
                </ol>
                
                <h4>🎯 Power User Features:</h4>
                <ul style="line-height: 1.8;">
                    <li><strong>Quick Triage:</strong> After running multiple analyses, click the 🚨 button to see all critical threats at once</li>
                    <li><strong>Correlation Analysis:</strong> Click 🔗 to find IPs appearing in multiple strategies - these are your highest-priority targets</li>
                    <li><strong>HTML Reports:</strong> Generate professional reports with the 📄 button for management briefings</li>
                    <li><strong>Export Options:</strong> All views support CSV export for further analysis in Excel or other tools</li>
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
        
        def on_help_click(b):
            show_tips()
        
        triage_button.on_click(on_triage_click)
        correlation_button.on_click(on_correlation_click)
        report_button.on_click(on_report_click)
        help_button.on_click(on_help_click)
        
        action_buttons = widgets.HBox([
            triage_button,
            correlation_button,
            report_button,
            help_button
        ], layout=widgets.Layout(justify_content='flex-start', margin='10px 0'))
        
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
