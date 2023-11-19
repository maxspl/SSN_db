import requests
import pandas as pd
from bs4 import BeautifulSoup
from pwn import *
import json
import argparse

def xor_data(data, key=0xDE):
    return bytearray([b ^ key for b in data])

def save_table_to_json_xored(APIs, url, filename):
    """Fetch the table from the URL and save it as a CSV file after applying XOR."""
    response = requests.get(url)
    if response.status_code == 200:
        soup = BeautifulSoup(response.content, 'html.parser')
        table = soup.find('table')
        df = pd.read_html(str(table))[0]

        df = df.fillna(0)
        df['ServiceName'] = df['ServiceName'].apply(lambda x: x[::-1])
        
        columns_to_convert = df.columns[2:]
        df[columns_to_convert] = df[columns_to_convert].astype(int)
        df.set_index('ServiceName', inplace=True)
        transposed_df = df.transpose()
        
        

        # Now convert the transposed DataFrame to JSON
        json_result = transposed_df.to_json()
        json_result_l = json.loads(json_result)
        filtered_data = {key: json_result_l[key] for key in APIs if key in json_result_l}
        json_result = json.dumps(filtered_data)
        #print("json_result :",json_result)

        # Convert JSON data to string and then to bytes
        json_string = json.dumps(json_result)
        json_string = str(json_result)
        
        json_bytes = json_string.encode('utf-8')

        # XOR the bytes
        xor_result = xor_data(json_bytes)
        # Convert to Base64
        base64_encoded = b64e(xor_result)
        with open(filename, 'w') as file:
            file.write(base64_encoded)
        return
    else:
        print("Failed to retrieve the webpage. Status code:", response.status_code)

def read_json_xored(filename):
    file = open(filename,"r")
    content_b64d_xored = b64d(file.read())
    
    content_b64d = xor_data(content_b64d_xored)
    content_b64d = json.loads(content_b64d)
    #print("content_b64d :",content_b64d)
    

def reverse_function_names(APIs):
    for index,function in enumerate(APIs):
        APIs[index] = APIs[index][::-1]
    return APIs

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser()
    parser.add_argument('-a',"--APIs", nargs='?', default='none',help="comma separated list of API functions - case sensitive. Use All for default SSN.", const='present without value')
    args = parser.parse_args()
    if args.APIs == "none" or  args.APIs == "present without value":
        print("[ERROR] - usage: get_SSN.py -APIs <comma separated list of API functions - case sensitive>")
        exit()
    
    if args.APIs.lower()  == "all": 
        APIs = ["NtAllocateVirtualMemory","NtWriteVirtualMemory","NtCreateThreadEx"]
    else :
        APIs = args.APIs.split(',')
    
    APIs = reverse_function_names(APIs)
    
    # URL of the webpage
    url = 'https://hfiref0x.github.io/NT10_syscalls.html'
    filename = 'data.jsonb'
    #APIs = ["NtAllocateVirtualMemory","NtWriteVirtualMemory","NtCreateThreadEx"]
    # Save the table to a CSV file
    try :
        save_table_to_json_xored(APIs, url, filename)
        print(f"Syscalls SSN json format have been written to {filename}. Data is xored with 0xde and converted to base64. Functions names are reversed.")
    except Exception as e:
        print("Error : ",e)

    try :
        read_json_xored(filename)
    except Exception as e:
        print("Error : ",e)
