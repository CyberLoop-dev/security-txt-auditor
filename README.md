<div align="center">

![Header](https://capsule-render.vercel.app/api?type=waving&color=0:0f172a,100:0d9488&height=170&section=header&text=security-txt-auditor&fontColor=ffffff&fontSize=38)

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=22&pause=1000&center=true&vCenter=true&width=620&lines=Audit+security.txt+locally;Validate+RFC+9116+fields;No+network+requests" alt="Typing title"/>

[![License](https://img.shields.io/github/license/CyberLoop-dev/security-txt-auditor)](LICENSE)
![Language](https://img.shields.io/github/languages/top/CyberLoop-dev/security-txt-auditor)
[![Stars](https://img.shields.io/github/stars/CyberLoop-dev/security-txt-auditor?style=social)](https://github.com/CyberLoop-dev/security-txt-auditor/stargazers)
![Last commit](https://img.shields.io/github/last-commit/CyberLoop-dev/security-txt-auditor)

<img src="assets/mark.svg" width="520" alt="Security document audit illustration"/>

</div>

## 🧭 Overview
A read-only Python command-line checker for a local [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116) `security.txt` file. It checks required fields, URI schemes, timestamps, duplicate singleton fields, and unknown extensions. It never contacts a website.

## ✨ Features
- 🛡️ Checks the required `Contact` and `Expires` fields.
- 🕒 Validates ISO 8601 expiry timestamps and reports expired files.
- 🔗 Checks contact and canonical URI schemes.
- 🧾 Reports duplicate and unknown fields with line context.
- 📦 Offers readable text and JSON output.

## 🖥️ Demo
Run the bundled sample file locally. There is no hosted demo.

## 🚀 Quick Start
```bash
python main.py
python main.py path/to/security.txt
python main.py path/to/security.txt --json
python -m unittest discover -s tests
```

## 🧰 Tech Stack
- Python 3.10+
- Standard library only: `argparse`, `datetime`, `json`, `urllib.parse`

## 🗂️ Folder Structure
```text
.
├── .well-known/security.txt
├── assets/mark.svg
├── tests/test_audit.py
├── main.py
├── requirements.txt
└── README.md
```

## 🗺️ Roadmap
- [ ] Optional strict-mode checks for additional RFC recommendations.
- [ ] SARIF output for CI integrations.
- [ ] More extension-field validation profiles.

## 🤝 Contributing
Open an issue with a reproducible example, then submit a focused pull request. Keep audits local and read-only.

## 📄 License
MIT. See [LICENSE](LICENSE).

<div align="center">

![Footer](https://capsule-render.vercel.app/api?type=waving&color=0:0d9488,100:0f172a&height=100&section=footer)

</div>
