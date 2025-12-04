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
from ionic_scripting_framework import isf
from strategies import HuntStrategy


class WatsonDashboard:
    """
    Interactive dashboard for threat hunting using various strategies.
    
    Connects to IONIC database via isf, dynamically builds UI based on
    selected table schema, and executes hunt strategies on the data.
    """
    
    def __init__(self, strategies: list):
        """
        Initialize the WatsonDashboard.
        
        Args:
            strategies: List of HuntStrategy objects to make available
        """
        self.strategies = strategies
        self.all_tables = []
        
        # UI Components - will be created per tab
        self.tab_widget = None
        self.strategy_tab_contents = {}
        
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
        
        Returns:
            List of table names
        """
        try:
            query = """
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema NOT IN ('information_schema', 'pg_catalog')
            ORDER BY table_name
            """
            df = isf.run_query(query)
            
            if df is not None and not df.empty:
                return df['table_name'].tolist()
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
            
            tab_data['table_search'].observe(make_table_search_handler(i), names='value')
            tab_data['load_table_button'].on_click(make_load_table_handler(i))
            tab_data['run_button'].on_click(make_run_analysis_handler(i))
            
            # Create strategy description with input details
            input_descriptions = self._get_input_descriptions(strategy)
            inputs_html = ""
            for inp, (desc, example) in input_descriptions.items():
                inputs_html += f"""
                <div style="margin: 10px 0; padding: 8px; background: #f8f9fa; border-left: 3px solid #007bff;">
                    <b>{inp}:</b> {desc}<br/>
                    <i style="color: #6c757d; font-size: 0.9em;">{example}</i>
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
                tab_data['limit_input'],
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
    
    def _display_sortable_results(self, df: pd.DataFrame, max_rows: int = 100):
        """
        Display results with sorting controls using ipywidgets.
        
        Args:
            df: DataFrame to display
            max_rows: Maximum number of rows to display (for performance)
        """
        # Limit rows for performance
        display_df = df.head(max_rows) if len(df) > max_rows else df.copy()
        
        # Create sorting controls
        sort_column = widgets.Dropdown(
            options=['(unsorted)'] + list(display_df.columns),
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
        
        # Create output area for the table
        table_output = widgets.Output()
        
        def update_table(change=None):
            """Update the displayed table based on sort settings."""
            with table_output:
                clear_output(wait=True)
                
                # Apply sorting
                if sort_column.value != '(unsorted)':
                    ascending = (sort_order.value == 'Ascending')
                    sorted_df = display_df.sort_values(
                        by=sort_column.value, 
                        ascending=ascending
                    )
                else:
                    sorted_df = display_df
                
                # Display the sorted dataframe
                display(HTML(sorted_df.to_html(index=False, max_rows=None)))
        
        # Attach observers
        sort_column.observe(update_table, names='value')
        sort_order.observe(update_table, names='value')
        
        # Initial display
        update_table()
        
        # Create the sortable table widget
        sort_controls = widgets.HBox([sort_column, sort_order])
        sortable_table = widgets.VBox([
            widgets.HTML("<h4>📊 Results</h4>"),
            sort_controls,
            table_output
        ])
        
        display(sortable_table)
        
        if len(df) > max_rows:
            print(f"\n⚠️ Showing first {max_rows} of {len(df)} rows for performance.")
    
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
            query = f"DESCRIBE {sanitized_table}"
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
        
        # Build SELECT query with sanitized identifiers and LIMIT
        try:
            # Sanitize all column names and table name
            sanitized_columns = [self._sanitize_identifier(col) for col in col_map.values()]
            sanitized_table = self._sanitize_identifier(current_table)
            
            # Validate and sanitize limit value (IntText widget provides basic validation)
            limit = max(1, min(1000000, int(tab_data['limit_input'].value)))
            
            query = f"SELECT {', '.join(sanitized_columns)} FROM {sanitized_table} LIMIT {limit}"
        except ValueError as e:
            with tab_data['output_widget']:
                print(f"❌ Invalid SQL identifier: {e}")
            return
        
        with tab_data['output_widget']:
            print(f"🔍 Running {strategy.name}...")
            print(f"📊 Query: {query}")
            print()
            
            try:
                # Execute query
                df = isf.run_query(query)
                
                if df is None or df.empty:
                    print("⚠️ Query returned no data.")
                    return
                
                print(f"✅ Retrieved {len(df)} rows from {current_table}")
                print()
                
                # Run strategy analysis
                print(f"🔬 Analyzing data with {strategy.name}...")
                result_df = strategy.analyze(df, col_map)
                
                if result_df is None or result_df.empty:
                    print("⚠️ Analysis returned no results.")
                    return
                
                print(f"✅ Analysis complete! Found {len(result_df)} results.")
                print()
                print("📈 Results (sortable by clicking column headers):")
                print("-" * 80)
                
                # Display results in sortable table
                self._display_sortable_results(result_df)
                
            except Exception as e:
                print(f"❌ Error during analysis: {e}")
                import traceback
                traceback.print_exc()
    
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
        
        # Arrange layout with tabs
        dashboard = widgets.VBox([
            header,
            widgets.HTML("<hr>"),
            self.tab_widget,
        ])
        
        # Display
        display(dashboard)
