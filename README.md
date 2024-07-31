# SharpDumpMDEConfig

## Overview

**DumpMDEConfig** is a C# console application designed to extract and display Microsoft Defender configuration and logs, including excluded paths, enabled ASR rules, allowed threats, protection history, and Exploit Guard protection history. The application provides options to output the data in a table or CSV format.

## Usage

### To run the application and output the results in list format:

```bash
DumpMDEConfig
```

### To run the application and output the results in table format:

```bash
DumpMDEConfig --TableOutput
```

### To run the application and output the results in CSV format:

```bash
DumpMDEConfig --CSVOutput
```

### To specify a custom file for table output:

```bash
DumpMDEConfig --TableOutput --TableOutputFile "CustomFile.txt"
```

## Features

### 1. Dumping Defender Excluded Paths

Extracts and displays the excluded paths configured in Microsoft Defender.

### 2. Dumping Enabled ASR Rules

Extracts and displays the enabled Attack Surface Reduction (ASR) rules in Microsoft Defender.

### 3. Dumping Allowed Threats

Extracts and displays the threats allowed by Microsoft Defender.

### 4. Dumping Defender Protection History

Extracts and displays the protection history from Microsoft Defender.

### 5. Dumping Exploit Guard Protection History

Extracts and displays the Exploit Guard protection history from Microsoft Defender.

### 6. Dumping Windows Firewall Exclusions

Extracts and displays the Windows Firewall exclusions.

## Contributing

Contributions are welcome! Please submit a pull request or open an issue to discuss your ideas or report bugs.

## Acknowledgments

This project was inspired by the [Invoke-DumpMDEConfig PowerShell script](https://github.com/BlackSnufkin/Invoke-DumpMDEConfig). Special thanks to the original authors for their work.

---
