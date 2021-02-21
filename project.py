import argparse
import glob
import os
import re

parser = argparse.ArgumentParser(description='Scan apache configuration files to find mal-configured settings in your server.')

parser.add_argument('--path', action='store', help='Path to apache configuration directory.', metavar='Scan path')

args = parser.parse_args()

if args.path == None:
    print('Please provide a path to scan.')
    exit()

def print_warnings(line_no, warnings):
    if len(warnings) > 0:
        print('\t- Warnings at line ' + str(i) + ':')
        for warning in warnings:
            print('\t\t- ' + warning)

def scan_for_headers(line):
    acao = re.search('Access-Control-Allow-Origin', line)
    acac = re.search('Access-Control-Allow-Credentials', line)
    acma = re.search('Cache-Control', line)
    acam = re.search('Access-Control-Allow-Methods', line)
    acah = re.search('Access-Control-Allow-Headers', line)

    return acao,acac,acma,acam,acah

print('\n\t\t##############################')
print('\t\t\tStart Scanning!')
print('\t\t##############################\n')

scan_pattern = os.path.join(args.path, '*.conf')
file_num = 1
for filepath in glob.glob(scan_pattern):
    conf_file = open(filepath, 'r')
    print(str(file_num) + ". Scan results for file " + filepath + ":")
    warnings_found = False
    i = 1
    for line in conf_file:
        warnings = []

        acao,acac,acma,acam,acah = scan_for_headers(line)

        if acao: # Access-Control-Allow-Origin
            x = re.findall("(ORIGIN_SUB_DOMAIN|\*)", line)
            if (len(x) > 0):
                warnings.append('Origin - be careful with who can access to your site ')
                warnings_found = True
        elif acac: # Access-Control-Allow-Credentials
            x = re.findall("\"false\"", line)
            if (len(x) > 0):
                warnings_found = True
                warnings.append('This site does not allow credentials')
        elif acah: # Access-Control-Allow-Headers
            x = re.findall("(Authorization|X-Requested-With|Content-Type|Refresh-Token)", line)
            if (len(x) > 0):
                if ('Authorization' not in  x):
                    warnings_found = True
                    warnings.append('site not allowed autherization at preflight request')
                if ('Authorization' in  x and 'Refresh-Token' not in x):
                    warnings_found = True
                    warnings.append('site allowed autherization but not allowed refresh token')
                if ('X-Requested-With' in  x and 'Content-Type' not in x):
                    warnings_found = True
                    warnings.append('missing defenition for preflight request')
                if re.search("\*", line):
                    warnings_found = True
                    warnings.append("Using wildcard, allowing all HTTP headers to be requested from server.")
        elif acma: # Access-Control-Max-Age
            if re.search("max-age=[1-9]+[0-9]*", line) is None:
                warnings_found = True
                warnings.append('Please use max-age header to define maximum time to allow caching for the resources.')
        elif acam: # Access-Control-Allow-Methods
            methods = re.findall("(GET|HEAD|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH|\*)", line)
            if '*' in methods:
                warnings_found = True
                warnings.append('Using wildcard, allowing all HTTP methods to get trough to server.')
            if 'POST' in methods:
                warnings_found = True
                warnings.append('Post method allowed - please be aware it can cause submition to a specified resource, often causing state change or side effects on the server.')
            if 'PUT' in methods:
                warnings_found = True
                warnings.append('Put method allowed - please be aware it can cause replacement of current representations of the target resource with the request payload.')
            if 'DELETE' in methods:
                warnings_found = True
                warnings.append('Delete method allowed - please be aware of resources deletions.')
            if 'CONNECT' in methods:
                warnings_found = True
                warnings.append('Connect method allowed - please be aware a tunnel could be established to the server, identified by a target resource.')
            if 'OPTIONS' in methods:
                warnings_found = True
                warnings.append('Options method allowed - please be aware that communication options for asked resource are publicly visible.')
            if 'TRACE' in methods:
                warnings_found = True
                warnings.append('Trace method allowed - please be aware a message loop-back test along the path to target resource is available.')
            if 'PATCH' in methods:
                warnings_found = True
                warnings.append('Patch method allowed - please be aware it can be used to apply partial moditfications fto a resource.')
        
        print_warnings(i, warnings)
        i += 1

    conf_file.close()
    if warnings_found == False:
        print("\tClean")
    print()
    warnings_found = False
    file_num += 1
print('\t\t##############################')
print('\t\t\tDone Scanning!')
print('\t\t##############################')
print()