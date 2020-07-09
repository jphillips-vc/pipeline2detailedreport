import json
import xml.etree.ElementTree as ET

flaws={}
five={}
four={}
three={}
two={}
one={}
zero={}

def getJSONdata():
	#
	# Importing JSON data
	#
	with open('results.json') as json_file:
		data = json.load(json_file)
		count=1
		#
		# Capturing Data from JSON results file and saving to dictionary
		#
		for i in data['results']['TestResults']['Issues']['Issue']:
			title=i['Title']
			issueid=i['IssueId']
			severity=i['Severity']
			issuetype=i['IssueType']
			cweid=i['CWEId']
			vcid=i['VCId']
			displaytext=i['DisplayText']
			src=i['Files']['SourceFile']['File']
			if "/" in src:
				src_file = src.split('/')
			elif "\\" in src:
				src_file = src.split('\\')
			src_file_len = len(src_file)
			file=''.join(src_file[src_file_len-1:])
			path=src.replace(file, '')
			line=i['Files']['SourceFile']['Line']
			qualifiedfunctionname=i['Files']['SourceFile']['QualifiedFunctionName']
			functionprototype=i['Files']['SourceFile']['FunctionPrototype']
			scope=i['Files']['SourceFile']['Scope']
			flaws[count]={'title' : title, 'issueid' : issueid, 'severity' : severity, 'issuetype' : issuetype, 'cweid' : cweid, 'vcid' : vcid, 'displaytext' : displaytext, 'file' : file, 'path' : path, 'line' : line, 'qualifiedfunctionname' : qualifiedfunctionname, 'functionprototype' : functionprototype, 'scope' : scope}
			count=count+1
		#
		# Place flaws in dictonary by severity
		#
		for x in flaws:
			if flaws[x]['severity'] == '5':
				five[x]={'title' : flaws[x]['title'], 'issueid' : flaws[x]['issueid'], 'severity' : flaws[x]['severity'], 'issuetype' : flaws[x]['issuetype'], 'cweid' : flaws[x]['cweid'], 'vcid' : flaws[x]['vcid'], 'displaytext' : flaws[x]['displaytext'], 'file' : flaws[x]['file'], 'path' : flaws[x]['path'], 'line' : flaws[x]['line'], 'qualifiedfunctionname' : flaws[x]['qualifiedfunctionname'], 'functionprototype' : flaws[x]['functionprototype'], 'scope' : flaws[x]['scope']}
			
			if flaws[x]['severity'] == '4':
				four[x]={'title' : flaws[x]['title'], 'issueid' : flaws[x]['issueid'], 'severity' : flaws[x]['severity'], 'issuetype' : flaws[x]['issuetype'], 'cweid' : flaws[x]['cweid'], 'vcid' : flaws[x]['vcid'], 'displaytext' : flaws[x]['displaytext'], 'file' : flaws[x]['file'], 'path' : flaws[x]['path'], 'line' : flaws[x]['line'], 'qualifiedfunctionname' : flaws[x]['qualifiedfunctionname'], 'functionprototype' : flaws[x]['functionprototype'], 'scope' : flaws[x]['scope']}
			
			if flaws[x]['severity'] == '3':
				three[x]={'title' : flaws[x]['title'], 'issueid' : flaws[x]['issueid'], 'severity' : flaws[x]['severity'], 'issuetype' : flaws[x]['issuetype'], 'cweid' : flaws[x]['cweid'], 'vcid' : flaws[x]['vcid'], 'displaytext' : flaws[x]['displaytext'], 'file' : flaws[x]['file'], 'path' : flaws[x]['path'], 'line' : flaws[x]['line'], 'qualifiedfunctionname' : flaws[x]['qualifiedfunctionname'], 'functionprototype' : flaws[x]['functionprototype'], 'scope' : flaws[x]['scope']}
			
			if flaws[x]['severity'] == '2':
				two[x]={'title' : flaws[x]['title'], 'issueid' : flaws[x]['issueid'], 'severity' : flaws[x]['severity'], 'issuetype' : flaws[x]['issuetype'], 'cweid' : flaws[x]['cweid'], 'vcid' : flaws[x]['vcid'], 'displaytext' : flaws[x]['displaytext'], 'file' : flaws[x]['file'], 'path' : flaws[x]['path'], 'line' : flaws[x]['line'], 'qualifiedfunctionname' : flaws[x]['qualifiedfunctionname'], 'functionprototype' : flaws[x]['functionprototype'], 'scope' : flaws[x]['scope']}
			
			if flaws[x]['severity'] == '1':
				one[x]={'title' : flaws[x]['title'], 'issueid' : flaws[x]['issueid'], 'severity' : flaws[x]['severity'], 'issuetype' : flaws[x]['issuetype'], 'cweid' : flaws[x]['cweid'], 'vcid' : flaws[x]['vcid'], 'displaytext' : flaws[x]['displaytext'], 'file' : flaws[x]['file'], 'path' : flaws[x]['path'], 'line' : flaws[x]['line'], 'qualifiedfunctionname' : flaws[x]['qualifiedfunctionname'], 'functionprototype' : flaws[x]['functionprototype'], 'scope' : flaws[x]['scope']}
			
			if flaws[x]['severity'] == '0':
				zero[x]={'title' : flaws[x]['title'], 'issueid' : flaws[x]['issueid'], 'severity' : flaws[x]['severity'], 'issuetype' : flaws[x]['issuetype'], 'cweid' : flaws[x]['cweid'], 'vcid' : flaws[x]['vcid'], 'displaytext' : flaws[x]['displaytext'], 'file' : flaws[x]['file'], 'path' : flaws[x]['path'], 'line' : flaws[x]['line'], 'qualifiedfunctionname' : flaws[x]['qualifiedfunctionname'], 'functionprototype' : flaws[x]['functionprototype'], 'scope' : flaws[x]['scope']}

def genXML():
	#root tag detailedreport
	xmldata = ET.Element('detailedreport')
	xmldata.set('xmlns', 'https://www.veracode.com/schema/reports/export/1.0')
	xmldata.set('xmlns:xsi', 'http://www.w3.org/2001/XMLSchema-instance')
	xmldata.set('account_id', '99999')
	xmldata.set('analysis_id', '9999999')
	xmldata.set('app_id', '999999')
	xmldata.set('app_name', 'Pipeline Scan')
	xmldata.set('assurance_level', '5')
	xmldata.set('build_id', '9999999')
	xmldata.set('business_criticality', '5')
	xmldata.set('business_owner', 'Not Specified')
	xmldata.set('business_unit', 'Not Specified')
	xmldata.set('first_build_submitted_date', '2000-01-01 00:00:00 UTC')
	xmldata.set('flaws_not_mitigated', '133')
	xmldata.set('generation_date', '2000-01-01 00:00:00 UTC')
	xmldata.set('grace_period_expired', 'true')
	xmldata.set('is_latest_build', 'true')
	xmldata.set('last_update_time', '2000-01-01 00:00:00 UTC')
	xmldata.set('legacy_scan_engine', 'false')
	xmldata.set('life_cycle_stage', 'Not Specified')
	xmldata.set('planned_deployment_date', '2000-01-01 00:00:00 UTC')
	xmldata.set('platform', 'Not Specified')
	xmldata.set('policy_compliance_status', 'None')
	xmldata.set('policy_name', 'Not Available')
	xmldata.set('policy_rules_status', 'None')
	xmldata.set('policy_version', '1')
	xmldata.set('report_format_version', '1.5')
	xmldata.set('sandbox_id', '9999999')
	xmldata.set('scan_overdue', 'false')
	xmldata.set('static_analysis_unit_id', '9999999')
	xmldata.set('submitter', 'Pipeline Scan')
	xmldata.set('tags', '')
	xmldata.set('teams', '')
	xmldata.set('total_flaws', '1')
	xmldata.set('veracode_level', 'VL1')
	xmldata.set('version', 'Pipeline Scan')
	xmldata.set('xsi:schemaLocation', 'https://www.veracode.com/schema/reports/export/1.0 https://analysiscenter.veracode.com/resource/detailedreport.xsd')

	### subtag named static-analysis
	static = ET.SubElement(xmldata, 'static-analysis')
	static.set('analysis_size_bytes', '9999999')
	static.set('engine_version', '9999999')
	static.set('published_date', '2019-07-18 20:44:55 UTC')
	static.set('rating', 'D')
	static.set('score', '0')
	static.set('submitted_date', '2019-07-18 20:44:55 UTC')
	static.set('version', 'pipeline scanner')
	### subtags under static-analysis for modules 
	sub_static_1 = ET.SubElement(static, 'modules')
	sub_sub_static_1 = ET.SubElement(sub_static_1, 'module')
	sub_sub_static_2 = ET.SubElement(sub_static_1, 'module')
	### subtag name severity
	severity5 = ET.SubElement(xmldata, 'severity')
	severity5.set('level', '5')
	### subtags under severity
	sub_sev_el_1 = ET.SubElement(severity5, 'category')
	sub_sev_el_1.set('categoryid', '999')
	sub_sev_el_1.set('categoryname', 'category name')
	sub_sev_el_1.set('pcirelated', 'false')
	
	###	sub sub tags under category
	# DESC
	sub_cat_el_1 = ET.SubElement(sub_sev_el_1, 'desc')
	# sub sub tags under desc
	sub_sub_cat_el_1 = ET.SubElement(sub_cat_el_1, 'para')
	sub_sub_cat_el_1.set('text', "Please consult sandbox or policy scan for more information.")

	# RECOMMENDATIONS
	sub_cat_el_2 = ET.SubElement(sub_sev_el_1, 'recommendations')
	# sub sub tags under recommendations
	sub_sub_cat_el_2 = ET.SubElement(sub_cat_el_2, 'para')
	sub_sub_cat_el_2.set('text', "Please consult sandbox or policy scan for more information.")

	# CWE
	sub_cat_el_3 = ET.SubElement(sub_sev_el_1, 'cwe')
	sub_cat_el_3.set('certc', '999')
	sub_cat_el_3.set('certcpp', '999')
	sub_cat_el_3.set('certjava', '999')
	sub_cat_el_3.set('cweid', '999')
	sub_cat_el_3.set('cwename', '999')
	sub_cat_el_3.set('owasp', '999')
	sub_cat_el_3.set('owasp2013', '999')
	sub_cat_el_3.set('pcirelated', 'false')
	sub_cat_el_3.set('sans', '999')
	# sub sub tags under CWE
	sub_cwe_el_1 = ET.SubElement(sub_cat_el_3, 'description')
	sub_sub_cwe_el_1 = ET.SubElement(sub_cwe_el_1, 'text')
	sub_sub_cwe_el_1.set('text', "Please consult sandbox or policy scan for more information.")
	sub_cwe_el_2 = ET.SubElement(sub_cat_el_3, 'staticflaws')
	# begin flaw loop
	for x in flaws:
		sub_sub_cwe_el_2 = ET.SubElement(sub_cwe_el_2, 'flaw')
		sub_sub_cwe_el_2.set('affects_policy_compliance', 'false')
		sub_sub_cwe_el_2.set('categoryid', '0')
		sub_sub_cwe_el_2.set('categoryname', flaws[x]['issuetype'])
		sub_sub_cwe_el_2.set('cia_impact', '')
		sub_sub_cwe_el_2.set('count', '1')
		sub_sub_cwe_el_2.set('cweid', flaws[x]['cweid'])
		sub_sub_cwe_el_2.set('date_first_occurrence', '2020-07-02 14:29:26 UTC')
		sub_sub_cwe_el_2.set('description', flaws[x]['displaytext'])
		sub_sub_cwe_el_2.set('exploitLevel', '0')
		sub_sub_cwe_el_2.set('functionprototype', flaws[x]['functionprototype'])
		sub_sub_cwe_el_2.set('functionrelativelocation', '0')
		sub_sub_cwe_el_2.set('grace_period_expires', '2019-07-18 17:43:20 UTC')
		sub_sub_cwe_el_2.set('issueid', str(x))
		sub_sub_cwe_el_2.set('line', flaws[x]['line'])
		sub_sub_cwe_el_2.set('mitigation_status', 'none')
		sub_sub_cwe_el_2.set('mitigation_status_desc', 'Not Mitigated')
		sub_sub_cwe_el_2.set('module', flaws[x]['file'])
		sub_sub_cwe_el_2.set('note', '')
		sub_sub_cwe_el_2.set('pcirelated', 'false')
		sub_sub_cwe_el_2.set('remediation_status', 'Open')
		sub_sub_cwe_el_2.set('remediationeffort', '0')
		sub_sub_cwe_el_2.set('scope', flaws[x]['scope'])
		sub_sub_cwe_el_2.set('severity', flaws[x]['severity'])
		sub_sub_cwe_el_2.set('sourcefile', flaws[x]['file'])
		sub_sub_cwe_el_2.set('sourcefilepath', flaws[x]['path'])
		sub_sub_cwe_el_2.set('type', '')


	### subtag name severity 4
	severity4 = ET.SubElement(xmldata, 'severity')
	severity4.set('level', '4')
	### subtag name severity 3
	severity3 = ET.SubElement(xmldata, 'severity')
	severity3.set('level', '3')
	### subtag name severity 2
	severity2 = ET.SubElement(xmldata, 'severity')
	severity2.set('level', '2')
	### subtag name severity 1
	severity1 = ET.SubElement(xmldata, 'severity')
	severity1.set('level', '1')
	### subtag name severity 0
	severity0 = ET.SubElement(xmldata, 'severity')
	severity0.set('level', '0')
	### subtag name severity 0
	flawstatus = ET.SubElement(xmldata, 'flaw-status')
	flawstatus.set('cannot-reproduce', '0')
	flawstatus.set('fixed', '0')
	flawstatus.set('new', '0')
	flawstatus.set('not_mitigated', '0')
	flawstatus.set('open', '0')
	flawstatus.set('reopen', '0')
	flawstatus.set('sev-1-change', '0')
	flawstatus.set('sev-2-change', '0')
	flawstatus.set('sev-3-change', '0')
	flawstatus.set('sev-4-change', '0')
	flawstatus.set('sev-5-change', '0')
	flawstatus.set('total', '0')
	### subtag name custom fields
	customfields = ET.SubElement(xmldata, 'customfields')
	sub_customfield1 = ET.SubElement(customfields, 'customfield')
	sub_customfield1.set('name', 'Custom 1')
	sub_customfield1.set('value', '')
	sub_customfield2 = ET.SubElement(customfields, 'customfield')
	sub_customfield2.set('name', 'Custom 2')
	sub_customfield2.set('value', '')
	sub_customfield3 = ET.SubElement(customfields, 'customfield')
	sub_customfield3.set('name', 'Custom 3')
	sub_customfield3.set('value', '')
	sub_customfield4 = ET.SubElement(customfields, 'customfield')
	sub_customfield4.set('name', 'Custom 4')
	sub_customfield4.set('value', '')
	sub_customfield5 = ET.SubElement(customfields, 'customfield')
	sub_customfield5.set('name', 'Custom 5')
	sub_customfield5.set('value', '')
	sub_customfield6 = ET.SubElement(customfields, 'customfield')
	sub_customfield6.set('name', 'Custom 6')
	sub_customfield6.set('value', '')
	sub_customfield7 = ET.SubElement(customfields, 'customfield')
	sub_customfield7.set('name', 'Custom 7')
	sub_customfield7.set('value', '')
	sub_customfield8 = ET.SubElement(customfields, 'customfield')
	sub_customfield8.set('name', 'Custom 8')
	sub_customfield8.set('value', '')
	sub_customfield9 = ET.SubElement(customfields, 'customfield')
	sub_customfield9.set('name', 'Custom 9')
	sub_customfield9.set('value', '')
	sub_customfield10 = ET.SubElement(customfields, 'customfield')
	sub_customfield10.set('name', 'Custom 10')
	sub_customfield10.set('value', '')
	# convert to XML
	report_xml = ET.tostring(xmldata)

	# write XML
	with open("detailed_report.xml", "wb") as f:
		f.write(report_xml)



def main():
	#
	# First Capture Data
	#
	getJSONdata()
	#
	# Generate XML
	#
	genXML()
  
main()