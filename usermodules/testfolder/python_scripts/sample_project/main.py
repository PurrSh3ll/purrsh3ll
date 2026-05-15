# main.py

# Import local module
import module1

# Import external Python library: Requests
import requests

def fetch_external_data(url):
    """Fetches data from the given URL using Requests."""
    try:
        # Use the Requests library
        response = requests.get(url)
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        return response.json()
    except requests.RequestException as e:
        return {"error": f"Error fetching data: {e}"}

def main():
    print("--- Starting main.py Program ---")

    # 1. Use function from Module 1 (which uses Pandas and imports Module 2)
    sample_data = {'Product': ['Laptop', 'Mouse', 'Keyboard'], 'Value': [1200, 25, 80]}

    # Call the function from module1.py
    df_final, calc_info = module1.process_data_with_pandas(sample_data)

    print("\n[Result from Module 1 (Pandas)]")
    print("Final DataFrame:")
    print(df_final)

    print(f"\n[Result from Module 2 (NumPy)]")
    print(calc_info)

    # 2. Use local function (which uses Requests)
    test_url = "https://jsonplaceholder.typicode.com/todos/1"
    json_data = fetch_external_data(test_url)

    print(f"\n[Result from Requests] (Data fetched from: {test_url})")
    print(f"Task Status: {json_data.get('completed')}")
    print(f"Title: {json_data.get('title')}")


if __name__ == '__main__':
    main()