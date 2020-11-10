import sys
import json
import argparse
import xml.etree.ElementTree as ET
#
# 
#
flaws={}
vulns={}
vsum={}
vulnlist=[]
topflawlist=[]
top25list=['79','787','20','125','119','89','200','416','352','78','190','22','476','287','434','732','94','522','611','798','502','269','400','306','862']
#
# Setup CLI Parser //  --html flag will create a local html report -f filename.json will pass a specific filename for your json file
#
parser = argparse.ArgumentParser(description='Accept flags from CLI')
parser.add_argument('-f', action="store", dest="f", help="Pass the filename of the pipeline scan json file")
parser.add_argument('--html', dest='html', action='store_true', help="Creates HTML report of the pipeline scan json file")
parser.add_argument('--no-html', dest='html', action='store_false', help="Default option prints no html report")
parser.set_defaults(html=False)
args = parser.parse_args()
htmlreport = args.html #parser.parse_args('html')
jsonfile = str(args.f)
if str(jsonfile) == "None":
	jsonfile = 'results.json'
else:
	jsonfile = str(args.f)
'''
########################
# DATA SCHEMA
########################
scan_id
scan_status
message
findings
	title
	issue_id
	gob
	severity
	issue_type_id
	issue_type
	cwe_id
	display_text
	files
		source_file
			file
			line
			function_name
			qualified_function_name
			function_prototype
			scope
	flaw_match
		procedure_hash
		prototype_hash
		flaw_hash
		flaw_hash_count
		flaw_hash_ordinal
		cause_hash
		cause_hash_count
		cause_hash_ordinal
########################
'''
#
# COUNT HOW MANY TIMES VAR IS FOUND
#
def count(dic, val):   
        sum = 0
        for key,value in dic.items():
            if value == val:
                sum += 1
            if type(value) is dict:
                sum += count(dic[key], val)
        return sum
#
# IMPORT JSON AND CAPTURE DATA
#
def getJSONdata():
	#
	# Importing JSON data
	#
	try:
		with open(jsonfile) as json_file:
			pipelinedata = json.load(json_file)
			#data2 = json.dumps(pipelinedata, indent=4)
			#print(data2)
			vulncount=0
			if pipelinedata['scan_status'] == "SUCCESS":
				for v in pipelinedata['findings']:
					title=v['title']
					issueid=str(v['issue_id'])
					severity=str(v['severity'])
					if severity == "5":
						sevname = "Very High"
					elif severity == "4":
						sevname = "High"
					elif severity == "3":
						sevname = "Medium"
					elif severity == "2":
						sevname = "Low"
					elif severity == "1":
						sevname = "Very Low"
					elif severity == "0":
						sevname = "Informational"
					issuetype=v['issue_type']
					cweid=v['cwe_id']
					displaytext=v['display_text']
					src=v['files']['source_file']['file']
					if "/" in src:
						src_file = src.split('/')
						src_file_len = len(src_file)
						file=''.join(src_file[src_file_len-1:])
					elif "\\" in src:
						src_file = src.split('\\')
						src_file_len = len(src_file)
						file=''.join(src_file[src_file_len-1:])
					else:
						src_file = src
						file = src_file
					path=src.replace(file, '')
					line=str(v['files']['source_file']['line'])
					qualifiedfunctionname=v['files']['source_file']['qualified_function_name']
					functionprototype=v['files']['source_file']['function_prototype']
					scope=v['files']['source_file']['scope']
					flaws[vulncount]={'title' : title, 'issueid' : issueid, 'severity' : severity, 'issuetype' : issuetype, 'cweid' : cweid, 'displaytext' : displaytext, 'file' : file, 'path' : path, 'line' : line, 'qualifiedfunctionname' : qualifiedfunctionname, 'functionprototype' : functionprototype, 'scope' : scope}
					vulns[vulncount]={'title' : title, 'issueid' : issueid, 'severity' : sevname, 'issuetype' : issuetype, 'cweid' : cweid, 'displaytext' : displaytext, 'file' : file, 'path' : path, 'line' : line, 'qualifiedfunctionname' : qualifiedfunctionname, 'functionprototype' : functionprototype, 'scope' : scope}
					vulnlist.append([str(cweid), str(sevname), str(title), str(issuetype), str(file), str(line), str(scope)])
					vulncount = vulncount + 1
			else:
				sys.exit("Pipeline scan status not successful")
	except:
		sys.exit("Error within capturing JSON data (see getJSONdata)")

#
# SORT BY DICT VALUE
#
def sort_by_values(dict):
    dict_len= {key: value for key, value in dict.items()}
    import operator
    sorted_key_list = sorted(dict_len.items(), key=operator.itemgetter(1), reverse=True)
    sorted_dict = [{item[0]: dict[item [0]]} for item in sorted_key_list]
    return sorted_dict
#
# HOW MANY FLAWS IN CWE TOP 25
#
def top25():
	t25count = 0
	try:
		for k, v in vulns.items():
			cwe = str(vulns[k]['cweid'])
			if cwe in top25list:
				t25count = t25count + 1

		return str(t25count)
	except:
		sys.exit("Error within defining Top 25 data (see top25)")
#
# GET VULN TOTALS BY SEVERITY
#
def vulnsummary(sev):

	vh=0
	h=0
	m=0
	l=0
	vl=0
	info=0
	try:
		for k, v in vulns.items():
			if vulns[k]['severity'] == "Very High":
				vh=vh+1	
			elif vulns[k]['severity'] == "High":
				h=h+1
			elif vulns[k]['severity'] == "Medium":
				m=m+1
			elif vulns[k]['severity'] == "Low":
				l=l+1
			elif vulns[k]['severity'] == "Very Low":
				vl=vl+1
			elif vulns[k]['severity'] == "Informational":
				info=info+1
		total = vh+h+m+l+vl+info
		vsum={'5' : vh, '4' : h, '3' : m, '2' : l, '1' : vl, '0' : info, 'total' : total}
		#print(vsum)
		return vsum[sev]
	except:
		sys.exit("Error within capturing vuln summary data (see vulnsummary)")
#
# PRINT VULNS FOR A SPECIFIC SEVERITY 
#
def getVulns(severity):
	try:
		for k, v in vulns.items():
			if str(severity) in vulns[k]['severity']:
				print(vulns[k])
	except:
		sys.exit("Error within capturing vuln data (see getVulns)")
#
# GET VULN DATA TABLE FOR HTML REPORT
#
def getVulnTable():
	vlistcounter=0
	vlistotal=len(vulnlist)
	s=""
	try:
		for x in vulnlist:
			if vlistcounter < (vlistotal-1):
				s+="[\""+ x[0] +"\", \""+ x[1] +"\", \""+ x[3] +"\", \""+ x[5] +"\", \""+ x[4] +"\", \""+ x[6] +"\"], "	
			else:
				s+="[\""+ x[0] +"\", \""+ x[1] +"\", \""+ x[3] +"\", \""+ x[5] +"\", \""+ x[4] +"\", \""+ x[6] +"\"]"
			vlistcounter=vlistcounter+1
		return s
	except:
		sys.exit("Error within capturing vuln table data (see getVulnTable)")
#
# FUNCTION TO CAPTURE TOP 5 FLAWS FOUND
#
def topflaws():
	d={}
	try:
		for y in vulns:
			key = vulns[y]["cweid"]
			results = count(vulns, key)
			issuetype = vulns[y]["issuetype"]
			if issuetype not in d:
				d[key] = []
			d[key].append(results)
			d[key].append(issuetype)
			d[key].append(key)

		for i in sort_by_values(d):
			h={}
			global s
			s=""
			for x in i:
				rec = "<h6><a href='https://cwe.mitre.org/data/definitions/"+str(i[x][2])+".html' target='_blank'>CWE "+str(i[x][2])+"</a></h6><p>"+str(i[x][1])+"("+str(i[x][0])+")</p>"
				topflawlist.append([str(rec)])

		r=[]	
		for i in range(5):
			r.append(' '.join(topflawlist[i]))

		return ' '.join(r)
	except:
		sys.exit("Error within capturing top flaw data (see topflaws)")


#
# OUTPUT HTML REPORT
#
def writeHTML():
	try:
		f = open("pipeline-report.html", "w")
		html1 = """<html>
			<head>
				<script src="https://unpkg.com/gridjs/dist/gridjs.production.min.js"></script>
				<link href="https://unpkg.com/gridjs/dist/theme/mermaid.min.css" rel="stylesheet" />
				<script type="module">import{Grid,html}from"https://unpkg.com/gridjs/dist/gridjs.production.es.min.js";</script>
				<script type="text/javascript" src="https://www.gstatic.com/charts/loader.js"></script>
			    <script type="text/javascript">
			      google.charts.load('current', {'packages':['corechart']});
			      google.charts.setOnLoadCallback(drawChart);
			      function drawChart() {
			        var data = google.visualization.arrayToDataTable([
			          ['Severity', 'Count'],
			          ['Very High',    """+str(vulnsummary('5'))+"""],
			          ['High',    """+str(vulnsummary('4'))+"""],
			          ['Medium',    """+str(vulnsummary('3'))+"""],		          
			          ['Low',     """+str(vulnsummary('2'))+"""],
			          ['Very Low',  """+str(vulnsummary('1'))+"""],
			          ['Informational',  """+str(vulnsummary('0'))+"""]
			        ]);
			        var options = {
			          slices: [{color: '#FF0000'}, {color: '#FF8C00'}, {color: '#e2e369'}, {color: '#37a2e4'}, {color: '#6600CC'}, {color: '#dddddd'}],
			          legend: {textStyle: {color: 'white'}},
			          backgroundColor: '#000000'
			        }
			        var chart = new google.visualization.PieChart(document.getElementById('piechart'));
			        chart.draw(data, options);
			      }
			    </script>
			    <style type="text/css">
			      html, body{font-family: Arial, Helvetica, sans-serif;}
			      h2{font-size: 1.5em; text-align: center;}
			      .header{height: 100px;}
			      button{border:none;}
			      .logo{width:300px; float: left;}
			      .report{max-width:800px; float: right;}
			      .report button{width:100px; padding:14px; border:none; border-radius: 25px;}
			      .report button a{color:#fff; text-decoration: none; font-weight: bold;}
			      .pink{background-color: #d73185;}
			      .column {float: left;}
			      .column a{color:#000;}
			      .column h5{margin: 0 auto; text-align: center; font-weight: bold; font-size:7.5em;}
			      .column h6{margin: 0 auto; text-align: center; font-variant: small-caps;}
			      .middle.column h6 {margin: 0 auto; text-align: center; font-variant: small-caps; line-height: 1.2; font-family: monospace; font-size: 1.25em; text-align: center; margin-left: 5px;}
				  .column p {margin-block-start: .1em;font-size: .75em;text-align: center;font-family: monospace;}
			      .row:after {content: ""; display: table; clear: both;}
			      .left{max-width:500px; width:50%;}
			      .left h2{color: #fff;}
			      .middle{max-width: 300px; height: 300px; width:25%; background-color:#e2e369;}
			      .right{max-width: 300px; height: 300px; width:25%; background-color: #37a2e4;}
			      #wrapper{width:100%; position: absolute;}
			      #container{max-width:1200px; min-height:1100px; margin: 0 auto;}
			      .row{width:100%; display: block; min-width:1100px;}
			      .chartruce{background-color: #e2e369;}
			      html,body{background-color:#000;}
			    </style>    
			  </head>
			  <body>
			    <div id="wrapper">
			      <div id="container">
			        <div class="row header">
			          <div class="logo">
			            <img src="https://community.veracode.com/resource/1544728435000/VeracodeCommunityLogo" alt="Home" width="250">
			          </div>
			          <div class="report"><button class="pink"><a href="https://help.veracode.com/reader/tS9CaFwL4_lbIEWWomsJoA/ovfZGgu96UINQxIuTqRDwg" target="_blank">Help!</a></button></div>
			        </div>
			        <div class="row">
			          <div class="left column">
			            <h2>PIPELINE SCAN RESULTS</h2>
			            <div id="piechart" style="width: 500px; height: 300px;"></div>
			          </div>
			          <div class="middle column"><h2>TOP FLAWS</h2>"""+str(topflaws())+"""</div>
			          <div class="right column"><h2>CWE TOP 25 FLAWS</h2><h5>"""+str(top25())+"""</h5></div>
			        </div>
			        <div class="row">
			          <div id="gridjs"></div>
			        </div>
			      </div>
			    </div>
			    <script src="https://unpkg.com/gridjs/dist/gridjs.development.js"></script>
			    <script type="text/javascript">
			      new gridjs.Grid({
			        columns: ["CWE", "SEVERITY", "ISSUE TYPE", "LINE", "FILE", "SCOPE"],
			        search: true,
			        sort: true,
			        pagination: true,
			        data: ["""+str(getVulnTable())+"""]
			      }).render(document.getElementById("gridjs"));
			    </script>
			  </body>
			</html>
			"""
		f.write(html1)
		f.close()
	except:
		sys.exit("Error creating html report (see writeHTML)")

#
# CREATE XML REPORT
#
def genXML():
	try:
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
	except:
		sys.exit("Error writing xml report (see genXML)")

def main():
	#
	# Load JSON data
	#
	getJSONdata()
	#
	# Write HTML report
	#
	writeHTML()
	#
	# Generate XML
	#
	genXML()
main()