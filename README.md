# 221B: The Analyst's Head-Up Display

**221B** is a Jupyter-based analytic dashboard designed to bridge the gap between **ALEX** (Compute) and **IONIC** (Storage).

It serves as a "No-Code" threat hunting interface, allowing analysts to execute complex statistical analysis and behavioral detection algorithms against Trino SQL datasets without writing a single line of code.

---

## 🎯 Mission

The volume of data in IONIC makes manual SQL querying slow and error-prone. **221B** automates the "heavy lifting" of data engineering. It dynamically parses table schemas, constructs optimized SQL queries via the `ionic_scripting_framework` (isf), and visualizes the results using Python's advanced data science libraries.

## ⚡ Core Modules

221B currently supports four distinct "Hunt Logic" modules:

### 1. The Beacon Hunter (C2 Detection)
* **Goal:** Identify Command & Control (C2) callbacks.
* **Method:** Aggregates connection timestamps per source/destination pair and calculates the standard deviation of "inter-arrival times" (deltas).
* **Output:** Histograms identifying "rhythmic" machine-like traffic vs. "chaotic" human traffic.

### 2. The Entropy Analyzer (DNS Tunneling)
* **Goal:** Detect data exfiltration or C2 hidden in protocol fields.
* **Method:** Applies Shannon Entropy math to string fields (DNS Queries, SSL Subjects).
* **Output:** Scatter plots highlighting high-entropy, long-string anomalies indicative of tunneling or DGA (Domain Generation Algorithms).

### 3. The Rare Artifact Finder (Outlier Detection)
* **Goal:** Spot unique/anomalous User-Agents, JA3 Hashes, or File Names.
* **Method:** Performs massive SQL aggregations to find the "Bottom 1%" of occurrences.
* **Output:** Ranked lists of the rarest artifacts seen on the network.

### 4. The Exfiltration Monitor (Producer/Consumer Ratio)
* **Goal:** Identify compromised internal hosts pushing data out.
* **Method:** Compares `orig_bytes` (upload) vs `resp_bytes` (download) to generate a traffic ratio.
* **Output:** Leaderboard of internal IPs behaving as "Producers" rather than "Consumers."

---

## 🛠 Technology Stack

* **Frontend:** Jupyter Notebook (ALEX Environment)
* **GUI Framework:** `ipywidgets` (Interactive controls), `ipydatagrid` (Data presentation)
* **Backend Connection:** `ionic_scripting_framework` (`isf`)
* **Data Processing:** `pandas`, `scipy.stats` (Entropy calculations)
* **Query Engine:** Trino SQL

---

## 🚀 Quick Start

### Prerequisites
Ensure you are operating within the ALEX environment and have access to the `ionic_scripting_framework`.

### Installation
1. Clone this repository into your ALEX workspace:
   ```bash
   git clone https://gitlab.mil/users/your-repo/221B.git
   ```
2. Open the main dashboard file:
   ```text
   221B_Dashboard.ipynb
   ```

### Usage
**221B** uses a "Wizard" style workflow:

1.  **Initialize:** Run the first cell to load libraries and authenticate with `isf`.
2.  **Select Dataset:** Use the dropdown to select a table (e.g., `zeek_conn`, `zeek_http`). 221B will automatically query the `information_schema` to populate the field options.
3.  **Map Fields:** The tool will ask "Which column is the Source IP?" Select the correct column from your dataset.
4.  **Run Hunt:** Click the module button (e.g., "Analyze Entropy").
5.  **Visualize:** View the resulting charts and data grids below the control panel.

---

## 🧩 Architecture

The project follows a modified Model-View-Controller (MVC) pattern:

* **`model.py`:** Handles `isf` connections and SQL query generation.
* **`view.py`:** Manages `ipywidgets` layout and plotting logic.
* **`controller.py`:** Binds user inputs to the model and updates the view.

**Example Connection Logic:**
```python
from ionic_scripting_framework import isf

def fetch_data(query):
    """
    Executes raw SQL against IONIC and returns a Pandas DataFrame.
    """
    try:
        data = isf.run_query(query)
        return data
    except Exception as e:
        print(f"Query Error: {e}")
        return None
```
