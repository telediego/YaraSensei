# YARA Sensei CLI

**YARA Sensei CLI** is a powerful command-line tool . It allows you to analyze, assess risk, and optimize YARA rules automatically by integrating VirusTotal intelligence and Google Gemini's generative capabilities.

---

## ✨ Key Features

- **Indicator of Compromise (IoC) Extraction**  
  Automatically parses the `strings` section of your YARA rule and extracts domains, IP addresses, hashes (MD5, SHA1, SHA256), and URLs using regular expressions.

- **Risk Assessment**  
  Queries the VirusTotal v3 API to check the reputation of the extracted indicators, providing an overall risk level (**LOW, HIGH, CRITICAL**).

- **AI-Assisted Optimization**  
  Uses Google Gemini to rewrite and enhance your original YARA rule, making it more precise, robust, and reducing the false positive rate.

- **File Generation**  
  Automatically saves the optimized rule to a new file with the `_fix.yar` suffix to avoid overwriting your original work.

---

## 🛠️ Prerequisites

Before running the script, make sure you have installed:

- Python 3.8+
- A VirusTotal API key (required for risk assessment)
- A Google Gemini / Google AI Studio API key (required for rule optimization)

---

## 🚀 Installation

### 1. Clone the repository

```bash
git clone https://github.com/your-username/yara-sensei-cli.git
cd yara-sensei-cli
```

### 2. Install required dependencies

You can install the required libraries using pip (using a virtual environment is recommended):

```bash
pip install requests google-generativeai python-dotenv
```

### 3. Configure environment variables

Create a file named `.env` in the root of the project and add your API keys:

```env
LLM_API_KEY=your_google_gemini_api_key_here
VT_API_KEY=your_virustotal_api_key_here
```

---

## 💻 Usage

The basic syntax to run the tool is:

```bash
python yara_sensei.py <path_to_yara_file> [-a {assess,enhance,all}]
```

### Arguments

- `file` (Required): The path to the YARA rule file (`.yar`) you want to analyze.
- `-a, --action` (Optional): The action you want to perform. If not specified, the default action (`all`) is executed.

### Actions

- `assess`: Only extracts indicators and queries VirusTotal.
- `enhance`: Only sends the rule to Gemini for optimization.
- `all`: (Default) Performs both actions.

---

## ▶️ Execution Examples

### Run everything (Assessment and Optimization)

```bash
python yara_sensei.py malware_rule.yar
```

### Only assess the risk of indicators with VirusTotal

```bash
python yara_sensei.py malware_rule.yar -a assess
```

### Only optimize and enhance the rule with Gemini

```bash
python yara_sensei.py malware_rule.yar -a enhance
```

---

## 📂 Example Workflow

You have a basic YARA rule in `test.yar` that looks for a suspicious IP and a hash.

Run:

```bash
python yara_sensei.py test.yar
```

### Assessment Output

The script will tell you if that IP or hash has malicious detections on VirusTotal.

### Optimization Output

The script will:
- Query Gemini
- Display improvement suggestions on the screen  
  *(e.g., "Added ascii wide modifiers to improve memory detection")*
- Create a file named `test_fix.yar` with the optimized rule ready to use

---

## ⚠️ Important Notes and Limitations

### Data Privacy (OPSEC)

Keep in mind that when using the `enhance` option, the contents of your YARA rule are sent to the Google Gemini API.

**Do not use this feature with:**
- Confidential organizational information
- Private data
- Indicators you do not wish to share with third parties

### API Limits

The script relies on the quotas of your VirusTotal and Google Gemini API keys.

If you analyze rules with many IoCs, you might hit rate limits (requests per minute), especially with the free VirusTotal API.

---

This is a personal project for learning about Yara
