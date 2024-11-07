#author: Kshitij
#github: https://github.com/krrysis
#email: kshitijshukla345@gmail.com

import os
import requests
import csv
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests_toolbelt.multipart.encoder import MultipartEncoder, MultipartEncoderMonitor

API_KEY = ''
API_UPLOAD_URL = 'https://www.virustotal.com/api/v3/files'
API_UPLOAD_URL_LARGE = 'https://www.virustotal.com/api/v3/files/upload_url'
API_ANALYSIS_URL = 'https://www.virustotal.com/api/v3/analyses'
API_FILE_URL = 'https://www.virustotal.com/api/v3/files'

headers = {
    "x-apikey": API_KEY
}

def create_callback(encoder, filename):
    encoder_len = encoder.len
    def callback(monitor):
        progress = (monitor.bytes_read / encoder_len) * 100
        print(f"Upload progress for {filename}: {progress:.2f}%")
    return callback

def upload_file(file_path, upload_url):
    filename = os.path.basename(file_path)
    with open(file_path, 'rb') as f:
        encoder = MultipartEncoder(fields={'file': (filename, f)})
        monitor = MultipartEncoderMonitor(encoder, create_callback(encoder, filename))
        response = requests.post(upload_url, headers={**headers, 'Content-Type': monitor.content_type}, data=monitor, verify=False)
        response.raise_for_status()
        return response.json()

def get_upload_url():
    response = requests.get(API_UPLOAD_URL_LARGE, headers=headers)
    response.raise_for_status()
    return response.json()['data']

def get_analysis_results(analysis_id):
    analysis_url = f"{API_ANALYSIS_URL}/{analysis_id}"
    response = requests.get(analysis_url, headers=headers)
    response.raise_for_status()
    return response.json()

def get_file_info(file_id):
    file_url = f"{API_FILE_URL}/{file_id}"
    response = requests.get(file_url, headers=headers)
    response.raise_for_status()
    return response.json()

def wait_for_analysis(analysis_id):
    while True:
        analysis_results = get_analysis_results(analysis_id)
        status = analysis_results['data']['attributes']['status']
        if status == 'completed':
            return analysis_results
        print(f"Waiting for analysis to complete for ID: {analysis_id}")
        time.sleep(15)

def process_file(file_path):
    filename = os.path.basename(file_path)
    try:
        print(f"Uploading file: {filename}")
        file_size = os.path.getsize(file_path)
        if file_size > 32 * 1024 * 1024:  # 32MB
            upload_url = get_upload_url()
            upload_response = upload_file(file_path, upload_url)
        else:
            upload_response = upload_file(file_path, API_UPLOAD_URL)
        
        print(f"Upload response: {upload_response}")
        analysis_id = upload_response['data']['id']
        print(f"Uploaded successfully. Analysis ID: {analysis_id}. Waiting for analysis results...")

        analysis_results = wait_for_analysis(analysis_id)
        print(f"Analysis results: {analysis_results}")

        file_id = analysis_results['meta']['file_info']['sha256']
        file_info = get_file_info(file_id)
        print(f"File info: {file_info}")

        stats = file_info['data']['attributes']['last_analysis_stats']
        malicious_count = stats['malicious']
        total_vendors = sum(stats.values())
        vt_link = f"https://www.virustotal.com/gui/file/{file_id}"

        return [filename, malicious_count, total_vendors, vt_link]
    except Exception as e:
        print(f"An error occurred with file {filename}: {e}")
        return [filename, 'Error', 'Error', 'Error']

def main():
    folder_path = input("Enter the folder path: ")
    output_csv = f"{os.path.basename(os.path.normpath(folder_path))}.csv"
    files_list = [os.path.join(root, filename) for root, dirs, files in os.walk(folder_path) for filename in files]
    
    with open(output_csv, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['File Name', 'Malicious Count', 'Total Vendors', 'VirusTotal Link'])
        
        with ThreadPoolExecutor() as executor:
            future_to_file = {executor.submit(process_file, file_path): file_path for file_path in files_list}
            for future in as_completed(future_to_file):
                result = future.result()
                writer.writerow(result)
                print(f"Results written to CSV for file: {result[0]}")

if __name__ == "__main__":
    main()
