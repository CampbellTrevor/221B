"""
app.py - Application controller for 221B threat hunting dashboard.

This module handles UI construction and database connection through
the ionic_scripting_framework (isf). It creates an interactive dashboard
using ipywidgets.
"""

import ipywidgets as widgets
from IPython.display import display, clear_output
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
        self.active_strategy = None
        self.current_table = None
        self.available_columns = []
        
        # UI Components
        self.output_widget = widgets.Output()
        self.table_search = None
        self.table_dropdown = None
        self.column_dropdowns = {}
        self.limit_input = None
        self.run_button = None
        self.column_mapping_container = None
        self.tab_widget = None
        self.strategy_tabs = {}
        
        # Initialize UI
        self._initialize_ui()
    
    def _initialize_ui(self):
        """Set up the initial UI components."""
        # Query available tables
        all_tables = self._get_available_tables()
        
        # Create table search box for filtering
        self.table_search = widgets.Text(
            placeholder='Search tables...',
            description='Filter:',
            style={'description_width': 'initial'}
        )
        self.table_search.observe(self._on_table_search, names='value')
        
        # Create table dropdown with all tables initially
        self.table_dropdown = widgets.Dropdown(
            options=all_tables,
            description='Select Table:',
            style={'description_width': 'initial'}
        )
        self.table_dropdown.observe(self._on_table_change, names='value')
        
        # Store all tables for filtering
        self.all_tables = all_tables
        
        # Container for dynamic column mappings
        self.column_mapping_container = widgets.VBox([])
        
        # Create limit input
        self.limit_input = widgets.IntText(
            value=10000,
            description='Row Limit:',
            min=1,
            max=1000000,
            style={'description_width': 'initial'}
        )
        
        # Create run button
        self.run_button = widgets.Button(
            description='Run Analysis',
            button_style='success',
            icon='search'
        )
        self.run_button.on_click(self._run_analysis)
        
        # Create tabs for strategies
        self._create_strategy_tabs()
        
        # Set initial strategy (first one)
        if self.strategies:
            self.active_strategy = self.strategies[0]
    
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
    
    def _create_strategy_tabs(self):
        """Create tab widget for strategies."""
        tab_contents = []
        
        for i, strategy in enumerate(self.strategies):
            # Create a description for each strategy
            description = widgets.HTML(
                value=f"""
                <div style="padding: 10px;">
                    <h3>{strategy.name}</h3>
                    <p><b>Required Inputs:</b> {', '.join(strategy.required_inputs)}</p>
                </div>
                """
            )
            tab_contents.append(description)
            self.strategy_tabs[i] = strategy
        
        # Create Tab widget
        self.tab_widget = widgets.Tab(children=tab_contents)
        
        # Set tab titles
        for i, strategy in enumerate(self.strategies):
            # Use first word as tab title, with fallback if name is empty or has no words
            name_parts = strategy.name.split()
            tab_title = name_parts[0] if name_parts else f"Strategy {i+1}"
            self.tab_widget.set_title(i, tab_title)
        
        # Observe tab changes
        self.tab_widget.observe(self._on_tab_change, names='selected_index')
    
    def _on_tab_change(self, change):
        """
        Handle tab selection change.
        
        Args:
            change: Change event from tab widget
        """
        selected_index = change['new']
        self.active_strategy = self.strategy_tabs[selected_index]
        
        # Rebuild column mappings for new strategy
        if self.current_table:
            self._build_column_mappings()
    
    def _on_table_search(self, change):
        """
        Handle table search/filter changes.
        
        Args:
            change: Change event from search text widget
        """
        search_term = change['new'].lower()
        
        if not search_term:
            # Show all tables if search is empty
            self.table_dropdown.options = self.all_tables
        else:
            # Filter tables based on search term
            filtered_tables = [t for t in self.all_tables if search_term in t.lower()]
            self.table_dropdown.options = filtered_tables if filtered_tables else ['No matching tables']
    
    def _on_table_change(self, change):
        """
        Handle table selection change.
        
        Queries the table schema and creates dropdowns for column mapping.
        
        Args:
            change: Change event from widget
        """
        self.current_table = self.table_dropdown.value
        
        if not self.current_table or self.current_table in ['No tables available', 'Error loading tables']:
            return
        
        # Get column information using DESCRIBE
        self.available_columns = self._get_table_columns(self.current_table)
        
        # Build column mapping UI
        self._build_column_mappings()
    
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
    
    def _build_column_mappings(self):
        """
        Build dropdown widgets for mapping strategy inputs to table columns.
        
        Creates one dropdown per required input of the active strategy.
        """
        if not self.active_strategy or not self.available_columns:
            self.column_mapping_container.children = []
            return
        
        # Create a dropdown for each required input
        dropdowns = []
        self.column_dropdowns = {}
        
        for required_input in self.active_strategy.required_inputs:
            dropdown = widgets.Dropdown(
                options=self.available_columns,
                description=f'{required_input}:',
                style={'description_width': 'initial'}
            )
            dropdowns.append(dropdown)
            self.column_dropdowns[required_input] = dropdown
        
        # Update container
        self.column_mapping_container.children = dropdowns
    
    def _run_analysis(self, button):
        """
        Execute the selected hunt strategy on the selected table.
        
        Args:
            button: Button widget that triggered this callback
        """
        # Clear previous output
        with self.output_widget:
            clear_output(wait=True)
        
        # Validate selections
        if not self.active_strategy:
            with self.output_widget:
                print("⚠️ Please select a hunt strategy.")
            return
        
        if not self.current_table or self.current_table in ['No tables available', 'Error loading tables']:
            with self.output_widget:
                print("⚠️ Please select a valid table.")
            return
        
        if not self.column_dropdowns:
            with self.output_widget:
                print("⚠️ Please select a table to load column mappings.")
            return
        
        # Build column mapping
        col_map = {}
        for required_input, dropdown in self.column_dropdowns.items():
            col_map[required_input] = dropdown.value
        
        # Build SELECT query with sanitized identifiers and LIMIT
        try:
            # Sanitize all column names and table name
            sanitized_columns = [self._sanitize_identifier(col) for col in col_map.values()]
            sanitized_table = self._sanitize_identifier(self.current_table)
            
            # Validate and sanitize limit value (IntText widget provides basic validation)
            limit = max(1, min(1000000, int(self.limit_input.value)))
            
            query = f"SELECT {', '.join(sanitized_columns)} FROM {sanitized_table} LIMIT {limit}"
        except ValueError as e:
            with self.output_widget:
                print(f"❌ Invalid SQL identifier: {e}")
            return
        
        with self.output_widget:
            print(f"🔍 Running {self.active_strategy.name}...")
            print(f"📊 Query: {query}")
            print()
            
            try:
                # Execute query
                df = isf.run_query(query)
                
                if df is None or df.empty:
                    print("⚠️ Query returned no data.")
                    return
                
                print(f"✅ Retrieved {len(df)} rows from {self.current_table}")
                print()
                
                # Run strategy analysis
                print(f"🔬 Analyzing data with {self.active_strategy.name}...")
                result_df = self.active_strategy.analyze(df, col_map)
                
                if result_df is None or result_df.empty:
                    print("⚠️ Analysis returned no results.")
                    return
                
                print(f"✅ Analysis complete! Found {len(result_df)} results.")
                print()
                print("📈 Top Results:")
                print("-" * 80)
                
                # Display results
                display(result_df.head(20))
                
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
            <p>Select a hunt strategy, choose your data source, map the columns, and run your analysis.</p>
            """
        )
        
        # Create table selection section
        table_section = widgets.VBox([
            widgets.HTML("<h3>Data Source</h3>"),
            self.table_search,
            self.table_dropdown,
        ])
        
        # Create analysis section
        analysis_section = widgets.VBox([
            widgets.HTML("<h3>Column Mapping</h3>"),
            self.column_mapping_container,
            self.limit_input,
            self.run_button,
        ])
        
        # Arrange layout with tabs for strategies
        controls = widgets.VBox([
            header,
            widgets.HTML("<hr>"),
            widgets.HTML("<h3>Hunt Strategy</h3>"),
            self.tab_widget,
            widgets.HTML("<hr>"),
            table_section,
            widgets.HTML("<hr>"),
            analysis_section,
            widgets.HTML("<hr>"),
        ])
        
        # Combine controls and output
        dashboard = widgets.VBox([
            controls,
            self.output_widget
        ])
        
        # Display
        display(dashboard)
