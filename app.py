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
        self.table_dropdown = None
        self.strategy_dropdown = None
        self.column_dropdowns = {}
        self.run_button = None
        self.column_mapping_container = None
        
        # Initialize UI
        self._initialize_ui()
    
    def _initialize_ui(self):
        """Set up the initial UI components."""
        # Query available tables
        tables = self._get_available_tables()
        
        # Create strategy dropdown
        strategy_names = [s.name for s in self.strategies]
        self.strategy_dropdown = widgets.Dropdown(
            options=strategy_names,
            description='Hunt Type:',
            style={'description_width': 'initial'}
        )
        self.strategy_dropdown.observe(self._on_strategy_change, names='value')
        
        # Create table dropdown
        self.table_dropdown = widgets.Dropdown(
            options=tables,
            description='Select Table:',
            style={'description_width': 'initial'}
        )
        self.table_dropdown.observe(self._on_table_change, names='value')
        
        # Container for dynamic column mappings
        self.column_mapping_container = widgets.VBox([])
        
        # Create run button
        self.run_button = widgets.Button(
            description='Run Analysis',
            button_style='success',
            icon='search'
        )
        self.run_button.on_click(self._run_analysis)
        
        # Set initial strategy
        if self.strategies:
            self.active_strategy = self.strategies[0]
            self._on_strategy_change(None)
    
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
    
    def _on_strategy_change(self, change):
        """
        Handle strategy selection change.
        
        Args:
            change: Change event from widget (can be None on init)
        """
        # Find the selected strategy
        selected_name = self.strategy_dropdown.value
        for strategy in self.strategies:
            if strategy.name == selected_name:
                self.active_strategy = strategy
                break
        
        # Rebuild column mappings for new strategy
        if self.current_table:
            self._build_column_mappings()
    
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
            identifier: Table or column name
        
        Returns:
            Sanitized identifier
        
        Raises:
            ValueError: If identifier contains invalid characters
        
        Note:
            Dots are allowed for schema-qualified names (e.g., schema.table).
            Since table/column names come from information_schema and DESCRIBE
            queries (system-controlled), the risk of malicious input is minimal.
            User cannot directly input these values - they select from dropdowns.
        """
        # Allow alphanumeric, underscore, and dot (for schema.table)
        if not re.match(r'^[a-zA-Z0-9_\.]+$', identifier):
            raise ValueError(f"Invalid identifier: {identifier}")
        return identifier
    
    def _get_table_columns(self, table_name: str) -> list:
        """
        Get columns for a specific table using DESCRIBE.
        
        Args:
            table_name: Name of the table
        
        Returns:
            List of column names
        """
        try:
            # Sanitize table name to prevent SQL injection
            sanitized_table = self._sanitize_identifier(table_name)
            query = f"DESCRIBE {sanitized_table}"
            df = isf.run_query(query)
            
            if df is not None and not df.empty:
                # DESCRIBE returns column info - try common column names
                # Most SQL systems use 'Column', 'column_name', or 'Field'
                for col_name in ['Column', 'column_name', 'Field', 'field']:
                    if col_name in df.columns:
                        return df[col_name].tolist()
                # Fallback to first column if none of the expected names found
                return df.iloc[:, 0].tolist()
            else:
                return []
        except Exception as e:
            print(f"Error describing table {table_name}: {e}")
            return []
    
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
        
        # Build SELECT query with sanitized identifiers
        try:
            # Sanitize all column names and table name
            sanitized_columns = [self._sanitize_identifier(col) for col in col_map.values()]
            sanitized_table = self._sanitize_identifier(self.current_table)
            query = f"SELECT {', '.join(sanitized_columns)} FROM {sanitized_table}"
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
        
        # Arrange layout
        controls = widgets.VBox([
            header,
            widgets.HTML("<hr>"),
            self.strategy_dropdown,
            self.table_dropdown,
            self.column_mapping_container,
            self.run_button,
            widgets.HTML("<hr>"),
        ])
        
        # Combine controls and output
        dashboard = widgets.VBox([
            controls,
            self.output_widget
        ])
        
        # Display
        display(dashboard)
