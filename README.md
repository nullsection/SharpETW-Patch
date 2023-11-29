# ETW-RIP

ETW (Event Tracing for Windows) is a Windows logging mechanism that allows capturing and analyzing system events. Blue teamers, who focus on defending and securing systems, can leverage ETW for various purposes, including detection and analysis of security-related events. Antivirus (AV) software also utilizes ETW to enhance its capabilities in detecting and responding to threats.

High-level summary of ETW use by blue teamers and AV for detection:

1. Event Collection: ETW enables the collection of a wide range of system events, including process creation, network activity, registry modifications, and more. Blue teamers and AV solutions can configure ETW to capture events related to suspicious or malicious activities.

2. Event Filtering: ETW supports the filtering of events based on specific criteria. Blue teamers and AV solutions can define filters to capture events relevant to their detection strategies, such as events from specific processes, network connections, or known malicious behaviors.

3. Real-Time Monitoring: ETW allows for real-time monitoring of events as they occur. Blue teamers and AV solutions can actively monitor and analyze events in real-time, enabling quick detection and response to potential threats or suspicious activities.

4. Anomaly Detection: By monitoring and analyzing patterns and anomalies in collected events, blue teamers and AV solutions can identify abnormal behaviors that might indicate malicious activity. These anomalies can include unusual process executions, unauthorized privilege escalations, suspicious network communications, and more.

5. Threat Hunting: ETW provides a rich dataset for proactive threat hunting. Blue teamers can search for specific event patterns or indicators of compromise (IOCs) across the collected event logs, helping to uncover hidden threats or advanced persistent threats (APTs).

6. Integration with Security Information and Event Management (SIEM) Systems: ETW logs can be ingested into SIEM systems, enabling centralized log management and correlation of events from multiple sources. This integration enhances the overall security monitoring and incident response capabilities.

7. Enhanced AV Capabilities: Antivirus solutions can leverage ETW to augment their threat detection capabilities. By monitoring relevant events, AV software can detect suspicious activities, analyze behavior patterns, and make more informed decisions regarding potential threats or malware.

Overall, ETW provides valuable insights and event data that blue teamers and AV solutions can utilize for detection, analysis, and response to security incidents. By leveraging the rich event information provided by ETW, these defenders can enhance their ability to identify, investigate, and mitigate potential threats in Windows environments.

## Patching in memory 
One common way people get around this is by patching NTDLL.DLL EtwEventWrite in memory. This basically means calculating the position in memory this is loaded, and patching in an operation to simply return when called. 

JMP EtwEventWrite -> EIP executes 0xC3 (op code for return). 

The benefit to this in C# in particular is you've completely bypassed ETW write events for your process. For blue teamers that rely on this, your process will go dark. Worth noting though, that any underlying kernel calls you make will still get hooked by ETW just not blatantly pointing at your process. 
