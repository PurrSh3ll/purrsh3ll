# module2.py

# Import external Python library: NumPy
import numpy as np

def calculate_something(data_list):
    """Calculates the mean of a list of data using NumPy."""
    # Create a NumPy array from the list
    np_array = np.array(data_list)
    # Calculate and return the mean
    average = np_array.mean()
    return f"The mean of the list {data_list} (calculated by NumPy) is: {average}"

# Simple test block
if __name__ == '__main__':
    result = calculate_something([10, 20, 30, 40, 50])
    print(result)