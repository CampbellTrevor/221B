"""
Mock module for ionic_scripting_framework (isf).
This is used for testing purposes when IONIC is not available.
"""

class MockISF:
    """Mock class for IONIC Scripting Framework."""
    
    def run_query(self, query):
        """Mock run_query method."""
        return None

# Create a global mock instance
isf = MockISF()
