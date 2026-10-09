\# 🔐 DVWA Brute Force Testing Tool



\## 📌 About the Project



The \*\*DVWA Brute Force Testing Tool\*\* is a Python-based cybersecurity project developed to understand how password-guessing attacks work in a controlled security lab.



The tool tests a predefined list of passwords against a local DVWA (Damn Vulnerable Web Application) login page. It identifies whether a password from the test wordlist matches the configured lab account and generates a report of the test results.



This project helps beginners understand authentication security, password weaknesses, and the importance of protecting login systems.



\## 🎯 Why Did We Build This Project?



Many web applications use username and password authentication. Weak passwords and insufficient login protection can make accounts vulnerable to repeated password attempts.



We built this project to:



\* Understand how password brute-force testing works.

\* Learn how Python sends HTTP requests to a web application.

\* Identify weak passwords in a controlled lab environment.

\* Understand authentication success and failure responses.

\* Generate reports that help review security test results.

\* Learn why rate limiting, account lockout, and strong passwords are important.



\## ⚙️ How Does It Work?



The project follows these steps:



1\. \*\*Target Configuration:\*\* The user provides the local DVWA URL and test username.

2\. \*\*Wordlist Loading:\*\* The tool reads candidate passwords from a text file.

3\. \*\*Authentication Testing:\*\* The tool submits password candidates to the DVWA login endpoint.

4\. \*\*Response Analysis:\*\* It examines the responses to determine whether an attempt succeeded or failed.

5\. \*\*Stop on Success:\*\* When a valid test password is identified, the testing process stops.

6\. \*\*Report Generation:\*\* The results are saved in JSON and CSV formats for later review.



\## 🛠️ Technologies Used



| Technology   | Purpose                                                           |

| ------------ | ----------------------------------------------------------------- |

| Python       | Main programming language                                         |

| HTTPX        | Sends HTTP requests and handles responses                         |

| Rich         | Displays readable output and progress in the terminal             |

| DVWA         | Intentionally vulnerable application used as the test environment |

| Docker       | Runs DVWA in an isolated local environment                        |

| JSON         | Stores structured test results                                    |

| CSV          | Stores results in a spreadsheet-friendly format                   |

| Git \& GitHub | Version control and project hosting                               |



\## 🧩 Main Features



\* Wordlist-based password testing in the local DVWA lab.

\* Configurable target URL and username.

\* Configurable delay between attempts.

\* Authentication response analysis.

\* Stop-on-success behaviour.

\* JSON and CSV report generation.

\* Separate website/API authentication assessment mode using explicitly supplied test credentials.



\## 🚀 How to Run the Project



\### 1. Clone the repository



```bash

git clone YOUR\_GITHUB\_REPOSITORY\_URL

cd dvwa-brute-force

```



Replace `YOUR\_GITHUB\_REPOSITORY\_URL` with your repository's actual URL.



\### 2. Create a virtual environment



```bash

python -m venv venv

```



\### 3. Activate the environment



\*\*Windows Command Prompt:\*\*



```cmd

venv\\Scripts\\activate

```



\### 4. Install dependencies



```bash

python -m pip install -r requirements.txt

```



\### 5. Start the local DVWA lab



Start your DVWA container and make sure the application is accessible at:



```text

http://localhost:8080

```



\### 6. Check the available commands



```bash

python brute\_tester.py --help

```



Use the arguments displayed by your installed version of the script.



\## 📊 Output and Reports



After a test, the tool can generate reports containing the recorded attempts and their results.



\* \*\*JSON report:\*\* Useful for structured data and further processing.

\* \*\*CSV report:\*\* Useful for viewing results in Excel or other spreadsheet applications.



The exact report location depends on the script configuration.



\## 🔒 Security Recommendations



This project demonstrates why authentication systems should use:



\* Strong, unique passwords.

\* Login rate limiting.

\* Temporary account lockout or progressive delays.

\* Multi-factor authentication (MFA).

\* Monitoring and alerting for repeated failed logins.



\## 📚 What I Learned



Through this project, I practised:



\* Python scripting for security testing.

\* HTTP requests and response handling.

\* Authentication workflow analysis.

\* Wordlist processing.

\* JSON and CSV report generation.

\* Using virtual environments and Python packages.

\* Git and GitHub for project version control.



\## ⚠️ Disclaimer



This project is intended for educational use and authorized security testing. Wordlist-based password testing should be performed only in the local DVWA lab or another explicitly approved environment within the permitted scope.



The tool is not intended for unauthorized access to real accounts or systems.



