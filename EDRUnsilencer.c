#include <windows.h>
#include <fwpmu.h>
#include <stdio.h>
#include <wchar.h>
#include <conio.h>  // For _getch()

// EDRUnsilencer: Monitoring and Removing WFP Block Rules
// ----------------------------------------------------------
// This tool demonstrates the ability to monitor custom outbound Windows Filtering Platform (WFP) block rules 
// that aim to block specific executables, particularly those set by tools like EDRSilencer and MDSec Fireblock. 
// These block rules, typically created for executables such as Defender, SentinelOne, and others, 
// prevent outbound IPv4/IPv6 traffic for specific processes. This tool enables real-time monitoring of such rules 
// and provides an option to remove them.
//
// EDRUnsilencer is inspired by the functionality of EDRSilencer and addresses a gap in many current EDR systems, 
// which often lack the capability to detect and remove malicious filtering rules at the WFP level. By demonstrating 
// this approach, EDRUnsilencer encourages EDR vendors to develop similar detection mechanisms.
//
// While this tool serves as a proof of concept, it is not designed for use in production environments. 
// Its purpose is to inspire EDR vendors and security professionals to explore similar approaches 
// for detecting and removing malicious filtering rules within their own solutions. This tool is 
// best suited for research, development, or security demonstrations, rather than for daily 
// operational use in live systems where more robust and scalable solutions are required.
//
// License: This software is released directly into the public domain under the Unlicense, making it freely 
// available for anyone to use, modify, and share without restrictions. Enjoy!
//
// Version: 1.0 (Stable)
// Author: Wilhelm-Jan Stiny
// License: Unlicense - https://unlicense.org/


// Manually define the GUID for FWPM_CONDITION_ALE_APP_ID
GUID ALEAppIdGUID = { 0xd78e1e87, 0x8644, 0x4ea5, { 0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71 } };

// Collect filter IDs for removal
UINT64 detectedFilters[100];
int filterCount = 0;  // Count of filters detected

// Function to remove filters by their IDs
void RemoveDetectedFilters() {
    HANDLE hEngine = NULL;
    DWORD result = 0;
    
    // Open the WFP filtering engine
    result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &hEngine);
    if (result != ERROR_SUCCESS) {
        printf("[!] EDRUnsilencer: Failed to open WFP engine for removal (Error code: 0x%x)\n", result);
        return;
    }

    // Remove each detected filter by ID
    for (int i = 0; i < filterCount; i++) {
        result = FwpmFilterDeleteById0(hEngine, detectedFilters[i]);
        if (result == ERROR_SUCCESS) {
            printf("[+] EDRUnsilencer: Successfully removed filter with ID: %llu\n", detectedFilters[i]);
        } else {
            printf("[!] EDRUnsilencer: Failed to remove filter with ID: %llu (Error code: 0x%x)\n", detectedFilters[i], result);
        }
    }

    // Close the engine handle after removal
    FwpmEngineClose0(hEngine);
}

int ListBlockActionFilters() {
    HANDLE hEngine = NULL;
    HANDLE enumHandle = NULL;
    FWPM_FILTER0** filters = NULL;
    DWORD result = 0;
    UINT32 numFilters = 0;
    filterCount = 0;  // Reset the filter count
    
    // Open the WFP filtering engine
    result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &hEngine);
    if (result != ERROR_SUCCESS) {
        printf("[!] EDRUnsilencer: Failed to open WFP engine for monitoring (Error code: 0x%x)\n", result);
        return 0;
    }
    
    // Enumerate all filters
    result = FwpmFilterCreateEnumHandle0(hEngine, NULL, &enumHandle);
    if (result != ERROR_SUCCESS) {
        printf("[!] EDRUnsilencer: Failed to create filter enumeration handle (Error code: 0x%x)\n", result);
        FwpmEngineClose0(hEngine);
        return 0;
    }
    
    int foundAnyFilter = 0;

    do {
        result = FwpmFilterEnum0(hEngine, enumHandle, 100, &filters, &numFilters);
        if (result != ERROR_SUCCESS) {
            printf("[!] EDRUnsilencer: Failed to enumerate filters (Error code: 0x%x)\n", result);
            break;
        }
        
        // Check each filter's action type and name
        for (UINT32 i = 0; i < numFilters; i++) {
            if (filters[i]->action.type == FWP_ACTION_BLOCK) {
                // Check if the filter name matches "Custom Outbound Filter"
                if (wcscmp(filters[i]->displayData.name, L"Custom Outbound Filter") == 0) {
                    if (foundAnyFilter == 0) {
                        printf("\n\n************ WARNING ************\n");
                        printf("!!! EDRUnsilencer: Custom outbound blocking filters detected !!!\n");
                    }
                    
                    // Mark that at least one filter was found
                    foundAnyFilter = 1;
                    
                    // Print the filter details
                    printf("Filter: %S (Filter ID: %llu)\n", filters[i]->displayData.name, filters[i]->filterId);

                    // Collect the filter ID for later removal
                    detectedFilters[filterCount++] = filters[i]->filterId;
                    
                    // Loop through filter conditions to find the App ID (Executable)
                    for (UINT32 j = 0; j < filters[i]->numFilterConditions; j++) {
                        if (IsEqualGUID(&filters[i]->filterCondition[j].fieldKey, &ALEAppIdGUID)) {
                            FWP_BYTE_BLOB* appId = filters[i]->filterCondition[j].conditionValue.byteBlob;
                            if (appId != NULL && appId->data != NULL) {
                                printf("Blocked Executable: %S\n", (WCHAR*)appId->data);
                            }
                        }
                    }
                }
            }
        }

        // Free the memory allocated for filters
        if (filters != NULL) {
            FwpmFreeMemory0((void**)&filters);
        }
        
    } while (numFilters != 0);
    
    // Clean up handles
    FwpmFilterDestroyEnumHandle0(hEngine, enumHandle);
    FwpmEngineClose0(hEngine);

    // Return 1 if filters were found
    return (foundAnyFilter > 0);
}

int main() {
    printf("[*] EDRUnsilencer entered monitoring state...\n");
    
    while (1) {  // Infinite loop to keep monitoring
        int foundFilter = ListBlockActionFilters();  // Run the filter check
        
        if (foundFilter) {
            printf("\n\nDo you want to remove the detected filters? (y/n)\n");

            // Wait for user input
            char decision = _getch();  // Wait for a key press
            if (decision == 'y' || decision == 'Y') {
                // Proceed to remove the detected filters
                printf("[*] Removing detected filters...\n");
                RemoveDetectedFilters();
                printf("[*] Filters removed. Returning to monitoring...\n");
            } else if (decision == 'q' || decision == 'Q') {
                printf("[*] EDRUnsilencer: Exiting...\n");
                break;  // Exit the loop and quit the program
            } else {
                printf("[*] Continuing monitoring without removing filters...\n");
            }
        }

        Sleep(10000);  // Wait for 10 seconds (10000 milliseconds) before the next check
    }

    return 0;
}
