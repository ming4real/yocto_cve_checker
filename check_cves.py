#!/usr/bin/env python3

# (c) Iain Menzies-Runciman
# SPDX-License-Identifier: MIT

import datetime
import json
import argparse
import logging
from enum import unique, IntEnum


#
# Define the error codes
#
@unique
class ReturnCodes(IntEnum):
    file_not_found = -1
    json_decode_error = -2
    no_data = -3
    unknown_type = -4


class Cves:
    def __init__(self):
        self.return_code = 0
        self.error_msg = ""
        self.current = {}
        self.patched = {}
        self.patched_now = {}
        self.patched_filename = "results/patched.json"
        self.unpatched = {}
        self.unpatched_now = {}
        self.unpatched_filename = "results/unpatched.json"
        self.changed_data = []
        self.changed = {
            "patched": [], 
            "unpatched": []
        }        
        self.changed_filename = "results/changed.json"

    def readJsonFile(self, filename: str = None, read_type: str = "current") -> bool:
        """Read JSON data from a file.
        """

        data = {}
        try:
            with open(filename) as file:
                try:
                    data = json.load(file)
                except json.decoder.JSONDecodeError:
                    self.return_code = ReturnCodes.json_decode_error
                    self.error_msg = f"Failed to decode the JSON from {filename}"
                    return False
                    
        except (FileNotFoundError, TypeError):
            if read_type == "current":
                self.return_code = ReturnCodes.file_not_found
                self.error_msg = f"Failed to find {filename}"
                return False
            else:
                # This just means that there is no history - the file may be created later
                pass
        
        if read_type == "current":
            self.current = data
        elif read_type == "patched":
            self.patched = data
        elif read_type == "unpatched":
            self.unpatched = data
        elif read_type == "changed":
            # Special case for changed data - need it to be a list
            if len(data) > 0:
                self.changed_data = data
            else:
                self.changed_data = []
        else:
            self.return_code = ReturnCodes.unknown_type
            self.error_msg = f"Unknown read type: {read_type}"
            return False

        self.return_code = 0
        self.error_msg = ""
        return True
        
    def checkCves(self) -> None:
        if len(self.current) == 0:
            # No current CVEs
            self.return_code = ReturnCodes.no_data
            self.error_msg = "No current data"
            return False
        
        # Loop through the packages
        for package in self.current['package']:
            name = package['name']
            layer = package['layer']
            version = package['version']
            products = package['products']            
            issues = package['issue']

            # Loop through the issues
            for issue in issues:
                issue_data = {
                    "name": name,
                    "layer":layer,
                    "version": version,
                    "issue": issue
                }
                # Check if we have seen it before
                id = issue['id']
                status = issue['status']
                if status == "Patched" or status == "Ignored":
                    self.patched_now[id] = issue_data

                    if self.unpatched.get(id):
                        # The issue has been now been patched
                        self.changed['patched'].append(issue_data)
                
                else:
                    if self.patched.get(id):
                        # It used to be patched, but is no longer!
                        self.changed['unpatched'].append(issue_data)

                    elif self.unpatched.get(id):
                        # We have seen it before and it is still unpatched
                        assessment = self.unpatched[id].get("assessment")
                        if assessment is None:
                            assessment = {}

                        issue_data["assessment"] = assessment
                    else:
                        # This is a new CVE
                        issue_data["assessment"] = {}
                        self.changed['unpatched'].append(issue_data)

                    self.unpatched_now[id] = issue_data

            # End for issues
        # End for packages

    def writeFiles(self):
        # Write the changes
        new_data = {
            "datetime": datetime.datetime.now().isoformat(), 
            "changes": self.changed
        }
        self.changed_data.append(new_data)

        with open(self.changed_filename, "w") as file:
            json.dump(self.changed_data, file, indent=4, sort_keys=True)
        
        # Write the patched data
        with open(self.patched_filename, "w") as file:
            json.dump(self.patched_now, file, indent=4)

        # Write the unpatched data
        with open(self.unpatched_filename, "w") as file:
            json.dump(self.unpatched_now, file, indent=4)




if __name__ == "__main__":
    cves = Cves()

    parser = argparse.ArgumentParser(description="Read and check CVEs from a Yocto build json file")
    parser.add_argument("filename", help="Filename of the JSON file from the Yocto build")
    parser.add_argument("--patched", help="Output Filename of the list of patched CVEs", default=cves.patched_filename)
    parser.add_argument("--unpatched", help="Output Filename of the list of unpatched CVEs", default=cves.unpatched_filename)
    parser.add_argument("--changed", help="Output Filename of the list of changes since the script was last run", default=cves.changed_filename)
    args = parser.parse_args()

    cves.readJsonFile(args.filename, read_type="current")
    cves.readJsonFile(cves.patched_filename, read_type="patched")
    cves.readJsonFile(cves.unpatched_filename, read_type="unpatched")
    cves.readJsonFile(cves.changed_filename, read_type="changed")

    cves.checkCves()
    cves.writeFiles()


