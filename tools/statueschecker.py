import pandas as pd
import requests
import concurrent.futures
import time
from urllib.parse import urlparse
import warnings
warnings.filterwarnings('ignore')

# Configuration
DEFAULT_INPUT_FILE = ""  # Default empty
DEFAULT_OUTPUT_FILE = "domain_status_results.csv"
TIMEOUT = 10  # Timeout in seconds for each request
MAX_WORKERS = 10  # Number of concurrent threads
RETRY_COUNT = 2  # Number of retries for failed requests

def clean_domain(domain):
    """Clean and normalize domain name"""
    if pd.isna(domain):
        return None
    
    domain = str(domain).strip().lower()
    
    # Remove protocols and paths
    if '://' in domain:
        domain = urlparse(domain).netloc
    
    # Remove paths and query strings
    if '/' in domain:
        domain = domain.split('/')[0]
    
    # Remove port numbers
    if ':' in domain:
        domain = domain.split(':')[0]
    
    # Remove www prefix (optional, comment out if you want to keep it)
    # domain = domain.replace('www.', '')
    
    return domain

def check_domain_status(domain):
    """Check a domain status for both HTTP and HTTPS"""
    result = {
        'domain': domain,
        'http_status': '',
        'http_status_code': '',
        'https_status': '',
        'https_status_code': '',
        'http_redirect': '',
        'https_redirect': '',
        'final_url_http': '',
        'final_url_https': ''
    }
    
    if not domain:
        return result
    
    # Check HTTP
    http_url = f"http://{domain}"
    for attempt in range(RETRY_COUNT):
        try:
            response = requests.get(http_url, 
                                  timeout=TIMEOUT, 
                                  allow_redirects=True,
                                  headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
            
            result['http_status_code'] = response.status_code
            result['final_url_http'] = response.url
            
            # Determine status category
            if 200 <= response.status_code < 300:
                result['http_status'] = 'Live'
            elif 300 <= response.status_code < 400:
                result['http_status'] = 'Redirect'
            elif 400 <= response.status_code < 500:
                result['http_status'] = 'Client Error'
            elif 500 <= response.status_code < 600:
                result['http_status'] = 'Server Error'
            
            # Check if redirected
            if response.history:
                result['http_redirect'] = 'Yes'
                redirect_chain = ' -> '.join([str(r.status_code) for r in response.history])
                result['http_redirect'] = f'Yes ({redirect_chain} -> {response.status_code})'
            break
            
        except requests.exceptions.SSLError:
            result['http_status'] = 'SSL Error'
            result['http_status_code'] = 'SSL_ERROR'
            break
        except requests.exceptions.ConnectionError:
            result['http_status'] = 'Connection Error'
            result['http_status_code'] = 'CONN_ERROR'
            break
        except requests.exceptions.Timeout:
            result['http_status'] = 'Timeout'
            result['http_status_code'] = 'TIMEOUT'
            break
        except Exception as e:
            if attempt == RETRY_COUNT - 1:
                result['http_status'] = 'Error'
                result['http_status_code'] = 'ERROR'
            else:
                time.sleep(1)
    
    # Check HTTPS
    https_url = f"https://{domain}"
    for attempt in range(RETRY_COUNT):
        try:
            response = requests.get(https_url, 
                                  timeout=TIMEOUT, 
                                  allow_redirects=True,
                                  headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
            
            result['https_status_code'] = response.status_code
            result['final_url_https'] = response.url
            
            # Determine status category
            if 200 <= response.status_code < 300:
                result['https_status'] = 'Live'
            elif 300 <= response.status_code < 400:
                result['https_status'] = 'Redirect'
            elif 400 <= response.status_code < 500:
                result['https_status'] = 'Client Error'
            elif 500 <= response.status_code < 600:
                result['https_status'] = 'Server Error'
            
            # Check if redirected
            if response.history:
                result['https_redirect'] = 'Yes'
                redirect_chain = ' -> '.join([str(r.status_code) for r in response.history])
                result['https_redirect'] = f'Yes ({redirect_chain} -> {response.status_code})'
            break
            
        except requests.exceptions.SSLError:
            result['https_status'] = 'SSL Error'
            result['https_status_code'] = 'SSL_ERROR'
            break
        except requests.exceptions.ConnectionError:
            result['https_status'] = 'Connection Error'
            result['https_status_code'] = 'CONN_ERROR'
            break
        except requests.exceptions.Timeout:
            result['https_status'] = 'Timeout'
            result['https_status_code'] = 'TIMEOUT'
            break
        except Exception as e:
            if attempt == RETRY_COUNT - 1:
                result['https_status'] = 'Error'
                result['https_status_code'] = 'ERROR'
            else:
                time.sleep(1)
    
    return result

def save_split_results(results_df, output_file):
    """Split results into Live, Redirection, and Not Live and save to separate files"""
    import os
    
    # Define criteria for categorization
    # A domain is 'Live' if either HTTP or HTTPS is 'Live'
    live_df = results_df[(results_df['http_status'] == 'Live') | (results_df['https_status'] == 'Live')]
    
    # A domain is 'Redirect' if it's not live but either is 'Redirect'
    redirect_df = results_df[
        ~((results_df['http_status'] == 'Live') | (results_df['https_status'] == 'Live')) & 
        ((results_df['http_status'] == 'Redirect') | (results_df['https_status'] == 'Redirect'))
    ]
    
    # Everything else is 'Not Live'
    not_live_df = results_df[
        ~((results_df['http_status'] == 'Live') | (results_df['https_status'] == 'Live')) & 
        ~((results_df['http_status'] == 'Redirect') | (results_df['https_status'] == 'Redirect'))
    ]
    
    # Save the files
    base_name = os.path.splitext(output_file)[0]
    
    live_file = f"{base_name}_live.csv"
    redirect_file = f"{base_name}_redirection.csv"
    not_live_file = f"{base_name}_not_live.csv"
    
    live_df.to_csv(live_file, index=False, encoding='utf-8-sig')
    redirect_df.to_csv(redirect_file, index=False, encoding='utf-8-sig')
    not_live_df.to_csv(not_live_file, index=False, encoding='utf-8-sig')
    
    print(f"\nSplit results saved to:")
    print(f"  - Live: {live_file} ({len(live_df)} domains)")
    print(f"  - Redirection: {redirect_file} ({len(redirect_df)} domains)")
    print(f"  - Not Live: {not_live_file} ({len(not_live_df)} domains)")

def process_domains(input_file, output_file):
    """Main function to process domains from Excel and save to CSV"""
    
    print(f"Reading domains from: {input_file}")
    
    try:
        # Check file extension and read accordingly
        if input_file.lower().endswith('.csv'):
            df = pd.read_csv(input_file)
        elif input_file.lower().endswith(('.xlsx', '.xls')):
            try:
                df = pd.read_excel(input_file, engine='openpyxl')
            except:
                df = pd.read_excel(input_file, engine='xlrd')
        else:
            # Try CSV by default if no extension
            df = pd.read_csv(input_file)
        
        print(f"Total rows found: {len(df)}")
        
        # Try to find domain column
        domain_column = None
        possible_columns = ['domain', 'Domain', 'DOMAIN', 'url', 'URL', 'website', 'Website', 
                          'site', 'Site', 'hostname', 'Hostname']
        
        for col in df.columns:
            if col.lower() in [c.lower() for c in possible_columns]:
                domain_column = col
                break
        
        # If no domain column found, use first column
        if domain_column is None:
            domain_column = df.columns[0]
            print(f"No standard domain column found. Using first column: '{domain_column}'")
        
        print(f"Using column: '{domain_column}'")
        
        # Clean domains
        domains = []
        for domain in df[domain_column]:
            cleaned = clean_domain(domain)
            if cleaned:
                domains.append(cleaned)
        
        print(f"Domains to check after cleaning: {len(domains)}")
        
        # Process domains with threading
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_domain = {executor.submit(check_domain_status, domain): domain 
                              for domain in domains}
            
            completed = 0
            for future in concurrent.futures.as_completed(future_to_domain):
                domain = future_to_domain[future]
                try:
                    result = future.result()
                    results.append(result)
                    completed += 1
                    
                    if completed % 10 == 0:
                        print(f"Progress: {completed}/{len(domains)} domains checked")
                        
                except Exception as e:
                    print(f"Error processing {domain}: {str(e)}")
                    results.append({
                        'domain': domain,
                        'http_status': 'Processing Error',
                        'http_status_code': '',
                        'https_status': 'Processing Error',
                        'https_status_code': '',
                        'http_redirect': '',
                        'https_redirect': '',
                        'final_url_http': '',
                        'final_url_https': ''
                    })
        
        # Create results DataFrame
        results_df = pd.DataFrame(results)
        
        # Save to CSV
        results_df.to_csv(output_file, index=False, encoding='utf-8-sig')
        print(f"\nFull results saved to: {output_file}")
        
        # Split and save results
        save_split_results(results_df, output_file)
        
        # Print summary
        print("\n" + "="*50)
        print("SUMMARY REPORT")
        print("="*50)
        
        print("\nHTTP Status Summary:")
        http_status_counts = results_df['http_status'].value_counts()
        for status, count in http_status_counts.items():
            print(f"  {status}: {count}")
        
        print("\nHTTPS Status Summary:")
        https_status_counts = results_df['https_status'].value_counts()
        for status, count in https_status_counts.items():
            print(f"  {status}: {count}")
        
        # Show sample of results
        print("\nSample Results (first 5):")
        print(results_df.head().to_string())
        
        return results_df
        
    except FileNotFoundError:
        print(f"Error: File not found at {input_file}")
        print("Please check if the file exists and the path is correct.")
        return None
    except Exception as e:
        print(f"Error: {str(e)}")
        return None

def main():
    """Main function"""
    print("\n" + "="*50)
    print("Domain Status Checker - HTTP & HTTPS")
    print("="*50)
    
    print("\nSelect input method:")
    print("1. Process file (CSV or Excel)")
    print("2. Enter domains manually")
    
    choice = input("\nEnter choice (1 or 2): ").strip()
    
    domains = []
    output_file = DEFAULT_OUTPUT_FILE
    
    if choice == '1':
        input_file = input("Enter input file path: ").strip().strip('"').strip("'")
        if not input_file:
            print("Error: No input file provided.")
            return
            
        output_file = input(f"Enter output CSV file path (default: {DEFAULT_OUTPUT_FILE}): ").strip().strip('"').strip("'")
        if not output_file:
            output_file = DEFAULT_OUTPUT_FILE
            
        # Process domains from file
        results = process_domains(input_file, output_file)
        if results is not None:
            print("\n[+] Process completed successfully!")
            
    elif choice == '2':
        domain_input = input("Enter domains (comma separated): ").strip()
        if not domain_input:
            print("Error: No domains provided.")
            return
            
        domains = [clean_domain(d) for d in domain_input.split(',')]
        domains = [d for d in domains if d]
        
        if not domains:
            print("Error: No valid domains found.")
            return
            
        output_file = input(f"Enter output CSV file path (default: {DEFAULT_OUTPUT_FILE}): ").strip().strip('"').strip("'")
        if not output_file:
            output_file = DEFAULT_OUTPUT_FILE
            
        # Process domains directly
        print(f"\nProcessing {len(domains)} domains...")
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_domain = {executor.submit(check_domain_status, domain): domain 
                              for domain in domains}
            
            completed = 0
            for future in concurrent.futures.as_completed(future_to_domain):
                result = future.result()
                results.append(result)
                completed += 1
                print(f"Progress: {completed}/{len(domains)} domains checked", end='\r')
        
        print("\nSaving results...")
        results_df = pd.DataFrame(results)
        results_df.to_csv(output_file, index=False, encoding='utf-8-sig')
        print(f"Full results saved to: {output_file}")
        
        # Split and save results
        save_split_results(results_df, output_file)
        
        # Summary
        print("\n" + "="*50)
        print("SUMMARY REPORT")
        print("="*50)
        print(f"Total checked: {len(results)}")
        print(results_df['http_status'].value_counts().to_string())
        
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    # Install required packages if not already installed
    try:
        import pandas
        import requests
        import openpyxl
    except ImportError:
        print("Missing required packages. Installing...")
        import subprocess
        import sys
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pandas", "requests", "openpyxl"])
        print("Packages installed. Please run the script again.")
        exit()
    
    main()