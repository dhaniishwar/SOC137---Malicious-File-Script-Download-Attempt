**Platform:** LetsDefend

**Lab Name:** SOC130 - Malicious File/Script Download Attempt

**Difficulty:** Easy

**Date Completed:** Aug 26, 2026

**Type:** Malware Detection

**Target:** NicolasPRD (172.16.17.37), user account "Nicolas"

---
<h3 align =center> GOAL </h3>

<br>
<br>
&nbsp;&nbsp;&nbsp;&nbsp; Determine whether a blocked macro-enabled word document was actually a malicious payload, confirm whether the malware executed or communication with a C2 server despite being "blocked", and close the case with the correct verdict and containment action.
<br>
<br>

---
<h3 align =center> Walkthrough </h3>

***Alert Review:***

<br>
<br>
&nbsp;&nbsp;&nbsp;&nbsp; Opening the alert in the Monitoring tab under the Investigation Channel reveals all the critical details. 
<br>
<br>

<img width="1026" height="341" alt="1" src="https://github.com/user-attachments/assets/d1449d45-9dd1-40a4-a900-8dc54a6e1c61" />

<br>
<br>
&nbsp;&nbsp;&nbsp;&nbsp; The file name is already a red flag before we start our analysis at all. the ".docm" extension means this is a macro-enabled word document, not the plain ".docx". Macro-enabled office file can execute code the moment a user click "Enable Content". The Device Action field is "Blocked", this tells us the delivery attempt was stopped at one control point, but it does not tells whether the file was already present or already executed somewhere else on the host or whether the user encountered it another way. we still have to verify that nothing have happened. Let's analyze this alert deeper by creating playbook.
<br>
<br>

---
***Starting the Playbook:***

<br>
<br>
&nbsp;&nbsp;&nbsp;&nbsp; Once you've reviewed the alert, head to Case Management and start the playbook. Think of the playbook as your structured checklist — it makes sure you don't skip steps under pressure.
<br>
<br>

<img width="591" height="208" alt="2" src="https://github.com/user-attachments/assets/8ee7b39a-711a-496c-bf1d-7aa6b0a663bb" />

<br>
<br>
&nbsp;&nbsp;&nbsp;&nbsp; The correct selection here is "Unknown or unexpected outgoing internet traffic", because the real risk in this case isn't the static file itself - it's what happens on the network after the file is opened.
<br>
<br>

<img width="537" height="259" alt="3" src="https://github.com/user-attachments/assets/7e9064ac-6332-4e29-b709-b5cc062a1d09" />

<br>
<br>
&nbsp;&nbsp;&nbsp;&nbsp; Let's head to log Management and Endpoint security, To see what happened really.
<br>
<br>

---
***Log Management and Endpoint Investigation:***

<img width="1037" height="269" alt="4" src="https://github.com/user-attachments/assets/bb2382f8-d8a2-481f-9ea8-1c664100c1e7" />

<img width="1015" height="293" alt="5" src="https://github.com/user-attachments/assets/3f4edf64-52da-4a1f-95bf-e1a5d83ef46c" />

<img width="955" height="257" alt="6" src="https://github.com/user-attachments/assets/428804c6-a1ba-4047-9a56-e5a7f6ec7a14" />


<br>
<br>
&nbsp;&nbsp;&nbsp;&nbsp; In this host's logs you may come across entries for iexplore.exe and powershell.exe reaching out to domain like ueba6ka.club and iluuryeqa.info, which look alarming at first glance but suspicious looking traffic is not automatically means your traffic. Unless it matches the exact C2 indicator tried to this specific file. when we search log management specifically for the c2 address associated with the "INVOICE PACKAGE" document, no match is found for this host, which means C2 request is "Not Accessed" according to log's 
<br>
<br>

<img width="746" height="457" alt="7" src="https://github.com/user-attachments/assets/b2569c77-cfdf-4849-80e6-ed3e7f494c11" />

<img width="761" height="414" alt="8" src="https://github.com/user-attachments/assets/9a2c3fb6-547a-4007-bdd2-f63b8c0098dd" />

<br>
<br>
&nbsp;&nbsp;&nbsp;&nbsp; Given that the Device Action is Blocked and Log Management search for the actual C2 request is "Not Accessed". This means, the malicious document was intercepted and the endpoint's security control "Quarantined" the file before its micro ever had the chance to establish outbound communication. 
<br>
<br>
&nbsp;&nbsp;&nbsp;&nbsp; We may come across other activity in the host's Terminal History during our revies. "rundll32.exe" launching a DLL out of a user's Temp folder or a heavily obfuscated PowerShell command consistent with a fileless loader. But unless we can tie that activity directly to this file's execution, we can't flag this in the case we are investigating. But this finding is suspicious worth investigating after this case.
<br>
<br>

---
***Malware Analyze:***

<img width="544" height="333" alt="9" src="https://github.com/user-attachments/assets/cee19778-c3d9-4eb2-b12c-e9e0962ab4bd" />

<br>
<br>
&nbsp;&nbsp;&nbsp;&nbsp; let's copy the hash from the alert and run the hash on VirusTotal to analyze.
<br>
<br>

<img width="1278" height="697" alt="11" src="https://github.com/user-attachments/assets/b6e68d1f-9482-4e9a-b99a-5cb63943ce42" />

<br>
<br>
&nbsp;&nbsp;&nbsp;&nbsp; VirusTotal results show 40/65 security vendors flagging the file as malicious. This was a high level of confirmation according to the virusTotal but we can't confirm it's malicious by just one tool. So, let's move on to AnyRUN.
<br>
<br>

<img width="1279" height="703" alt="10" src="https://github.com/user-attachments/assets/2f1c2712-5863-48cb-9e5a-bd411e09dcca" />

<br>
<br>
&nbsp;&nbsp;&nbsp;&nbsp;  Running the file hash on the AnyRUN confirms the file is malicious and with the all chain processes. Based on Virustotal and AnyRUN, We can confirm that this file is a "Malicious".
<br>
<br>

<img width="560" height="308" alt="12" src="https://github.com/user-attachments/assets/90a16c0b-1e3d-44fe-8356-8418dc8987d8" />

<br>
<br>
&nbsp;&nbsp;&nbsp;&nbsp; We have already confirm that C2 request was "Not Accessed" By Log Management Investigation.
<br>
<br>

---
***Documentation:***

<br>
<br>
&nbsp;&nbsp;&nbsp;&nbsp;  This was the area, where we log our IOCs so they can be used for future detection and threat hunting across the environment. We add three artifacts: Target Host IP and Hash of the file.
<br>
<br>

<img width="560" height="358" alt="13" src="https://github.com/user-attachments/assets/b887bb52-8135-464c-84a5-bf8ac49a3921" />

<br>
<br>
&nbsp;&nbsp;&nbsp;&nbsp; The Analyst Note is where I write the full story in plain language, as if explaining it to someone who wasn't there for any of the investigation.
<br>
<br>

<img width="557" height="330" alt="14" src="https://github.com/user-attachments/assets/d316f8f6-29a8-4eb3-bda0-6edadef22d6a" />

<br>
<br>
&nbsp;&nbsp;&nbsp;&nbsp; The case is closed as a "True Positive".
<br>
<br>

---
<h3 align =center> Summary </h3>

<br>
<br>
&nbsp;&nbsp;&nbsp;&nbsp;  This alert involved a macro-enabled word document named "INVOICE PACKAGE LINK TO DOWNLOAD.docm", which was sent to the endpoint NicolasPRD and has its Device Action recorded as Blocked. Third-party analysis confirmed the file was genuinely malicious: VirusTotal flagged it 40/65 and AnyRUN Sandboxing showed it function as a loaded that reaches out to filetranfer.io to fetch a second payload. A targeted search of Log Management for this file's actual C2 address found no matching traffic from the host and Endpoint security confirmed the file was Quarantined, meaning the attack was intercepted before it could execute. Separately, unrelated suspicious activity was also observed on the same host - rundll32 launching a DLL from Temp, obfuscated PowerShell and traffic to unfamiliar domains. But since none of it tried back to this specific file's execution chain, it was flagged for its own escalation rather than folded into this case. Based on all of this, the playbook was closed as "True Positive".
<br>
<br>
