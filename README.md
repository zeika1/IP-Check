# 🛡️ IP-Check: High-Speed Hosting & Data Center Scanner

**IP-Check** is a high-performance Python utility designed to scan thousands of IP addresses and determine if they belong to **Web Hosting providers**, **Data Centers**, or **Residential ISPs**. 

---

## 🚀 Key Features
* **Parallel Processing:** Uses `ThreadPoolExecutor` to check 10+ IPs at once.
* **Triple-Key Rotation:** Automatically splits your IP list into chunks for 3 different API keys.
* **Smart CSV Parsing:** Automatically detects delimiters (`,` or `:`) and removes duplicates.

---

## 🛠️ Installation & Setup

1. **Install Dependencies:**
   ```bash
   pip install pandas requests# IP-Check
## 💻 Platform Options

| Platform | File | Usage |
| :--- | :--- | :--- |
| **Linux / CLI** | `ipcheck.py` | `python3 ipcheck.py data.csv` |
| **Windows / GUI** | `ipcheck_win.py` | Double-click or `python ipcheck.py` (pops up a file picker) |
