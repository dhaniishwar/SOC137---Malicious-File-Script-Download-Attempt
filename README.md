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




