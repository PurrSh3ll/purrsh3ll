# module1.py

# Import local module
from module2 import calculate_something

# Import external Python library: Pandas
import pandas as pd


def process_data_with_pandas(data_dict):
    """Creates a DataFrame from data and returns it."""
    # Create a Pandas DataFrame
    df = pd.DataFrame(data_dict)

    # Use the function from the imported module2 to process the 'Value' column
    value_list = df['Value'].tolist()

    # Call the function from module2.py
    calculation_result = calculate_something(value_list)

    return df, calculation_result


# Simple test block
if __name__ == '__main__':
    data = {'Category': ['A', 'B', 'C'], 'Value': [100, 200, 300]}
    df_result, calc_info = process_data_with_pandas(data)
    print("--- Module 1 - Test ---")
    print("DataFrame:")
    print(df_result)
    print("Result from Module 2:", calc_info)