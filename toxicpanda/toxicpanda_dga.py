import hashlib
import re
from datetime import datetime, timezone, timedelta
from dateutil.relativedelta import relativedelta

def dga_domain_hash_substring(i):
    """Generates a domain hash substring based on a fixed day of the month."""
    # Set the date to the given day (i) at 00:00:00 UTC
    date_str = (datetime.now(timezone.utc).replace(day=1, hour=0, minute=0, second=0, microsecond=0) + relativedelta(months=i)).strftime("%Y-%m-%d %H:%M:%S")

    # Generate MD5 hash of the formatted date string
    md5_hash = hashlib.md5(date_str.encode()).hexdigest()

    # Extract substring based on the first letter found
    match = re.search("[a-zA-Z]", md5_hash[2:])  # Ignore first 2 chars
    if match:
        return md5_hash[2 + match.start(): 2 + match.start() + 10]
    else:
        return md5_hash[1:11]  # Fallback if no letters found

# Example usage
# Always 1 domain per month

i = 0 # Starting at the current month
num_months = 12 # next number of months

if __name__ == "__main__":

    while i < num_months:
        hash_result = dga_domain_hash_substring(i)
        print(hash_result)
        i += 1