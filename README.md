# pipeline2detailedreport
<b>USAGE:  python detailedrerport.py [--html] [-f filename.json]</b>
		
--html will generate a local html report from the json file
		
-f will allow you to pass a custom named json file from a completed pipeline scan

Note: The default behavior will not create an html report and uses the standard results.json generated file


<b>STEPS</b>
	
	- Place detailedreport.py in your pipeline output folder where your results.json file resides.
	
	- Run python detailedreport.py

	- A new file will be created called detailed_report.xml

	- Goto your IDE where you have your Veracode Static IDE plugin installed
	
	- From the Veracode menu, choose "view results" and proceed with uploading your detailed_report.xml file

This will give you the ability to import your Veracode Pipeline Scan results into your IDE for remediation.
