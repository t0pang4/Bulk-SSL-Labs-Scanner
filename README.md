This script takes in a text file with a list of domains to test with the SSL Server Test. A summary of the results are displayed in the shell. A folder is created in your current working directory with files containing the full json results of each scan.

## Running the Script
#### 1. Install depencies
```bash 
pip install -r requirements.txt
```
#### 2. Call the script
```python
python scanner.py -i "domains.txt" [-o]
```
**-o** *is an optional argument if you want results from cache rather than starting a new assessment.*

*Included an example text file with 2 domains.*
